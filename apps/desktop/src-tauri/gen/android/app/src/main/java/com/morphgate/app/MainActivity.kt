package com.morphgate.app

import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updateLayoutParams

class MainActivity : TauriActivity() {
  private var webView: WebView? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // Edge to edge (as every app is from Android 15), the window no longer shrinks for the
    // keyboard, and the WebView doesn't report it to the page: the WebView ends where the keyboard
    // begins, so the terminal and its extra keys stay above it. What that leaves is behind the
    // keyboard. On the WebView's parent, which passes the insets on: the WebView reads them itself
    // (the status bar's become the page's safe area).
    ViewCompat.setOnApplyWindowInsetsListener(findViewById<View>(android.R.id.content)) { _, insets ->
      val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
      webView?.takeIf { it.layoutParams is ViewGroup.MarginLayoutParams }?.updateLayoutParams<ViewGroup.MarginLayoutParams> {
        bottomMargin = keyboard
      }
      insets
    }
  }

  override fun onWebViewCreate(webView: WebView) {
    this.webView = webView
  }
}
