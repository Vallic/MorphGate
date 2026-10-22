//! Tauri shell: bridges `mg-ssh` sessions to xterm.js tabs in the webview.

mod agents;
#[cfg(target_os = "android")]
mod android;
mod attachments;
#[cfg(target_os = "android")]
mod biometric;
mod bulk;
mod cloud;
mod device;
mod host_cas;
mod host_import;
#[cfg(not(target_os = "android"))]
mod keychain;
mod links;
mod moving;
mod offboard;
mod orgs;
mod password;
mod proxy;
mod renew;
mod session_log;
mod sftp;
mod snippet_import;
mod ssh;
mod sync;
mod themes;
mod tunnels;
mod update;
mod util;
mod vault;
mod vpn;

use std::time::Duration;

use tauri::Manager;

/// openconnect starts MorphGate's own binary as its tun script and, for single sign-on, as its
/// external browser (see `mg_vpn::openconnect`); in that case act as that helper instead of
/// starting the app.
pub fn tun_helper_if_requested() {
    #[cfg(unix)]
    if std::env::args().nth(1).as_deref() == Some(vpn::OC_HELPER_ARG) {
        mg_vpn::openconnect::tun_helper_main();
    }
}

/// The name the running app answers to (on Linux, a D-Bus name): the app's identifier and this
/// user's data folder, where the vault is. A second launch with the same vault finds it; apps
/// with other data folders (several people side by side on one desktop, as the e2e runs them)
/// are separate.
#[cfg(desktop)]
fn single_instance_id(identifier: &str) -> String {
    use std::hash::{Hash, Hasher};
    let folder = std::env::var_os("XDG_DATA_HOME")
        .filter(|d| !d.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::home_dir().map(|h| h.join(".local/share")))
        .unwrap_or_default();
    let mut hash = std::hash::DefaultHasher::new();
    folder.hash(&mut hash);
    format!("{identifier}.d{:016x}", hash.finish())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // MORPHGATE_LOG (a filter: `debug`, `mg_sync=debug,morphgate_desktop_lib=debug`, …): what the
    // app does, on stderr, for troubleshooting. Off unless set; nothing from a vault is logged.
    if let Ok(filter) = std::env::var("MORPHGATE_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_writer(std::io::stderr)
            .try_init();
    }
    let context = tauri::generate_context!();
    let builder = tauri::Builder::default();
    // One app per vault: opening a link (or the app again) starts a second process, which hands
    // its link to the one already running and exits. First, as the plugin asks.
    #[cfg(desktop)]
    let builder = builder.plugin(
        tauri_plugin_single_instance::Builder::new()
            .callback(|app, _argv, _cwd| links::show(app))
            .dbus_id(single_instance_id(&context.config().identifier))
            .build(),
    );
    let builder = builder.plugin(tauri_plugin_deep_link::init());
    // Phones update through their app store.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(biometric::init());
    let app = builder
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            #[cfg(target_os = "android")]
            if let Err(e) = android::init_tls() {
                tracing::error!("{e}");
            }
            let data_dir = app.path().app_data_dir()?;
            let changed = std::sync::Arc::new(tokio::sync::Notify::new());
            app.manage(vault::VaultState::open(
                &data_dir.join("vault.sqlite3"),
                changed.clone(),
            )?);
            app.manage(ssh::SshState::new(data_dir));
            app.manage(sync::SyncState::new(changed));
            app.manage(vpn::VpnManager::default());
            app.manage(cloud::CloudState::default());
            app.manage(sftp::SftpState::default());
            app.manage(update::UpdateState::default());
            app.manage(links::Links::default());
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                // An AppImage isn't installed: it registers the scheme itself (packages and
                // installers do it when they install).
                #[cfg(target_os = "linux")]
                if app.env().appimage.is_some()
                    && let Err(e) = app.deep_link().register_all()
                {
                    tracing::warn!("registering morphgate:// links: {e}");
                }
                let handle = app.handle().clone();
                app.deep_link()
                    .on_open_url(move |event| links::received(&handle, event.urls()));
                // Opened by a link.
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    links::received(app.handle(), urls);
                }
            }
            sync::spawn_loop(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ssh::ssh_connect,
            ssh::ssh_write,
            ssh::ssh_resize,
            ssh::ssh_disconnect,
            ssh::hostkey_answer,
            sftp::sftp_open,
            sftp::sftp_close,
            sftp::sftp_list,
            sftp::sftp_mkdir,
            sftp::sftp_rename,
            sftp::sftp_remove,
            sftp::sftp_chmod,
            sftp::sftp_download,
            sftp::sftp_upload,
            sftp::sftp_cancel,
            sftp::local_home,
            sftp::local_list,
            sftp::local_mkdir,
            vault::vault_status,
            vault::vault_create,
            vault::vault_unlock,
            vault::vault_lock,
            vault::vault_recover,
            vault::vault_change_password,
            vault::vault_export,
            vault::identities_list,
            vault::identity_save,
            vault::identity_delete,
            vault::groups_list,
            vault::group_save,
            vault::group_delete,
            attachments::attachments,
            attachments::attachment_add,
            attachments::attachment_save,
            attachments::attachment_delete,
            moving::items_move_plan,
            moving::items_move,
            vault::vault_new_recovery_code,
            device::device_status,
            device::keychain_enable,
            device::keychain_disable,
            device::vault_unlock_keychain,
            device::presence_require,
            device::presence_setup,
            device::set_auto_lock,
            device::set_auto_update_check,
            update::about,
            update::update_check,
            update::update_install,
            vault::hosts_list,
            vault::host_save,
            vault::host_delete,
            bulk::items_delete,
            bulk::hosts_set_group,
            proxy::host_allow_proxy,
            host_cas::host_cas_list,
            host_cas::host_ca_save,
            host_cas::host_ca_delete,
            host_cas::host_certified_by,
            renew::key_renewal,
            renew::key_allow_renewal,
            renew::key_renew,
            vault::keys_list,
            vault::key_generate,
            vault::key_import,
            vault::key_delete,
            vault::key_certificate,
            cloud::cloud_sources,
            cloud::vallic_sign_in,
            cloud::vallic_sign_in_poll,
            cloud::cloud_refresh,
            cloud::cloud_sign_out,
            cloud::cloud_source_delete,
            cloud::cloud_source_key,
            cloud::cloud_check,
            cloud::cloud_cli_path,
            cloud::cloud_source_add,
            cloud::cloud_source_settings,
            cloud::cloud_add_key,
            cloud::cloud_feed_add,
            cloud::cloud_feed_settings,
            cloud::cloud_auto_refresh,
            agents::agents_list,
            orgs::orgs_locked,
            links::links_take,
            links::links_peek,
            links::links_add_invite,
            host_import::import_preview,
            host_import::import_hosts,
            vault::snippets_list,
            vault::snippet_save,
            vault::snippet_delete,
            vault::snippet_sent,
            snippet_import::snippets_read_csv,
            snippet_import::snippets_csv_example,
            tunnels::forwards_list,
            tunnels::forward_save,
            tunnels::forward_delete,
            tunnels::forward_start,
            tunnels::forward_stop,
            sync::sync_status,
            sync::sync_presence,
            password::password_strength,
            password::password_suggest,
            sync::sync_check,
            sync::sync_start_registration,
            sync::sync_enable,
            sync::sync_sign_in,
            sync::sync_join,
            sync::sync_recover_sign_in,
            sync::sync_sign_in_again,
            sync::sync_devices,
            sync::sync_revoke_device,
            sync::sync_now,
            sync::sync_disable,
            sync::sync_account,
            sync::sync_totp_start,
            sync::sync_totp_enable,
            sync::sync_totp_disable,
            sync::sync_email_start,
            sync::sync_email_change,
            sync::sync_open_portal,
            sync::sync_export_account,
            sync::sync_delete_account,
            sync::sync_accept_terms,
            util::open_link,
            vpn::vpns_list,
            vpn::vpn_save,
            vpn::vpn_delete,
            vpn::vpn_test,
            vpn::vpn_prompt_answer,
            orgs::sharing_status,
            orgs::vaults_list,
            orgs::orgs_list,
            orgs::org_create,
            orgs::org_vault_create,
            orgs::org_members,
            orgs::org_invite,
            orgs::org_invites,
            orgs::org_invite_cancel,
            orgs::invite_preview,
            orgs::invite_peek,
            orgs::invite_accept,
            orgs::member_confirm,
            orgs::member_role,
            orgs::member_remove,
            orgs::vault_access,
            orgs::vault_access_set,
            orgs::vault_access_revoke,
            orgs::vault_rotate,
            orgs::org_transfer,
            orgs::org_delete,
            orgs::org_details,
            orgs::org_policies_set,
            orgs::org_activity,
            orgs::member_keys,
            orgs::member_key_publish,
            orgs::member_key_unpublish,
            offboard::offboard_summary,
            offboard::offboard_scan,
            offboard::offboard_clean,
            offboard::key_replace,
            ssh::host_pinned_key,
            orgs::org_sso_status,
            orgs::org_device_requests,
            orgs::org_member_recertify,
            orgs::org_events_export,
            orgs::org_device_decide,
            orgs::org_sso_start,
            session_log::session_logs,
            session_log::session_log_cast,
            session_log::session_log_save,
            session_log::session_log_delete,
            session_log::session_logs_retry,
            themes::themes_list,
            themes::theme_import,
            themes::theme_delete,
            themes::terminal_settings,
            themes::terminal_settings_set,
        ])
        .build(context)
        .expect("error while starting MorphGate");
    app.run(|app, event| {
        // Quitting, and restarting into an update: stop tunnels, file transfers and VPNs
        // properly (an openconnect child would otherwise outlive the app).
        if let tauri::RunEvent::Exit = event {
            tauri::async_runtime::block_on(async {
                let stop = async {
                    app.state::<ssh::SshState>().stop_all_tunnels().await;
                    app.state::<sftp::SftpState>().close_all().await;
                    app.state::<vpn::VpnManager>().shutdown_all().await;
                };
                let _ = tokio::time::timeout(Duration::from_secs(3), stop).await;
            });
        }
    });
}
