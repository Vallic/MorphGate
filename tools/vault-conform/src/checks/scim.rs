//! SCIM 2.0 provisioning (outside vault-sync/v1), with an organization's token from the
//! operator: `--scim ORG_ID:TOKEN`.

use reqwest::Method;
use serde_json::{Value, json};

use crate::report::{ensure, shown};
use crate::{Ctx, Report};

const G: &str = "scim";

async fn call(
    method: Method,
    url: &str,
    token: &str,
    body: Option<Value>,
) -> Result<(u16, Value), String> {
    let mut req = reqwest::Client::new()
        .request(method, url)
        .bearer_auth(token)
        .header("accept", "application/scim+json")
        .timeout(std::time::Duration::from_secs(30));
    if let Some(b) = body {
        req = req
            .header("content-type", "application/scim+json")
            .body(b.to_string());
    }
    let resp = req.send().await.map_err(shown)?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(shown)?;
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

pub async fn run(ctx: &Ctx, r: &mut Report) {
    let plan = [
        (
            "GET /scim/v2/{org}/ServiceProviderConfig",
            "describes what is supported",
        ),
        (
            "POST /scim/v2/{org}/Users",
            "provisions a user (and refuses a duplicate)",
        ),
        ("GET /scim/v2/{org}/Users", "filters users by userName"),
        ("PATCH /scim/v2/{org}/Users/{id}", "deactivates a user"),
        (
            "PUT /scim/v2/{org}/Users/{id}",
            "refuses a changed userName (400 mutability)",
        ),
        ("DELETE /scim/v2/{org}/Users/{id}", "deletes a user"),
    ];
    let Some((org, token)) = ctx.opts.scim.clone() else {
        for (e, w) in plan {
            r.skip(G, e, w, "pass --scim ORG_ID:TOKEN to check provisioning");
        }
        return;
    };
    let base = format!("{}/scim/v2/{org}", ctx.opts.server);
    r.check(G, plan[0].0, plan[0].1, async {
        let (status, body) = call(
            Method::GET,
            &format!("{base}/ServiceProviderConfig"),
            &token,
            None,
        )
        .await?;
        ensure(status == 200, format!("status {status}"))?;
        ensure(
            body["patch"]["supported"] == true && body["filter"]["supported"] == true,
            format!("{body}"),
        )?;
        let (wrong, _) = call(Method::GET, &format!("{base}/Users"), "scim_wrong", None).await?;
        ensure(
            wrong == 401,
            format!("a wrong token got {wrong}, expected 401"),
        )
    })
    .await;
    let email = ctx.email("scim");
    let Some(id) = r
        .check(G, plan[1].0, plan[1].1, async {
            let user = json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": email, "active": true });
            let (status, body) = call(Method::POST, &format!("{base}/Users"), &token, Some(user.clone())).await?;
            ensure(status == 201, format!("status {status}: {body}"))?;
            let id = body["id"].as_str().ok_or("no id")?.to_owned();
            let (again, body) = call(Method::POST, &format!("{base}/Users"), &token, Some(user)).await?;
            ensure(again == 409 && body["scimType"] == "uniqueness", format!("a duplicate got {again}: {body}"))?;
            Ok(id)
        })
        .await
    else {
        for (e, w) in &plan[2..] {
            r.skip(G, e, w, "needs a provisioned user");
        }
        return;
    };
    r.check(G, plan[2].0, plan[2].1, async {
        let filter = format!("userName eq \"{email}\"");
        let url = reqwest::Url::parse_with_params(
            &format!("{base}/Users"),
            &[("filter", filter.as_str())],
        )
        .map_err(shown)?;
        let (status, body) = call(Method::GET, url.as_str(), &token, None).await?;
        ensure(
            status == 200 && body["totalResults"] == 1,
            format!("status {status}: {body}"),
        )
    })
    .await;
    r.check(G, plan[3].0, plan[3].1, async {
        let patch = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{ "op": "replace", "path": "active", "value": false }] });
        let (status, body) = call(Method::PATCH, &format!("{base}/Users/{id}"), &token, Some(patch)).await?;
        ensure(status == 200 && body["active"] == false, format!("status {status}: {body}"))
    })
    .await;
    r.check(G, plan[4].0, plan[4].1, async {
        let user = json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": ctx.email("other"), "active": false });
        let (status, body) = call(Method::PUT, &format!("{base}/Users/{id}"), &token, Some(user)).await?;
        ensure(status == 400 && body["scimType"] == "mutability", format!("status {status}: {body}"))
    })
    .await;
    r.check(G, plan[5].0, plan[5].1, async {
        let (status, _) = call(Method::DELETE, &format!("{base}/Users/{id}"), &token, None).await?;
        ensure(status == 204, format!("status {status}"))?;
        let (gone, _) = call(Method::GET, &format!("{base}/Users/{id}"), &token, None).await?;
        ensure(gone == 404, format!("fetching it again got {gone}"))
    })
    .await;
}
