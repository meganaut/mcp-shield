use askama::Template;
use axum::{
    Router,
    extract::Path,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use mcpcondor_ui::{assets::StaticAssets, mock};

fn render<T: Template>(t: T) -> Html<String> {
    Html(t.render().expect("template render"))
}

async fn page_login() -> Html<String> { render(mock::login(None)) }
async fn page_login_err() -> Html<String> { render(mock::login(Some("Invalid username or password".into()))) }
async fn page_dashboard() -> Html<String> { render(mock::dashboard()) }
async fn page_integrations() -> Html<String> { render(mock::integrations()) }
async fn page_agents() -> Html<String> { render(mock::agents()) }
async fn page_profiles() -> Html<String> { render(mock::profiles()) }
async fn page_audit() -> Html<String> { render(mock::audit()) }

async fn page_profile_detail() -> Html<String> { render(mock::profile_detail()) }
async fn page_agent_detail() -> Html<String> { render(mock::agent_detail()) }
async fn page_integration_tools() -> Html<String> { render(mock::integration_tools()) }

async fn page_logo() -> Html<String> {
    Html(r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Logo Design</title>
  <style>
    body { background: #f3f4f6; font-family: sans-serif; padding: 40px; }
    .row { display: flex; gap: 32px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 40px; }
    .swatch { display: flex; flex-direction: column; align-items: center; gap: 8px; }
    .swatch label { font-size: 11px; color: #666; }
    .dark { background: #1a1f2e; padding: 16px; border-radius: 8px; }
    h2 { font-size: 13px; color: #888; margin: 24px 0 12px; text-transform: uppercase; letter-spacing: .05em; }
    .wordmark { display:flex; align-items:center; gap:10px; font-family:sans-serif; font-weight:700; font-size:22px; color:#4F46E5; }
    .wordmark-dark { display:flex; align-items:center; gap:10px; font-family:sans-serif; font-weight:700; font-size:22px; color:#818cf8; }
  </style>
</head>
<body>

<h1 style="font-size:20px;font-weight:700;margin-bottom:8px">MCPCondor — Logo Iterations</h1>
<p style="color:#666;font-size:13px;margin-bottom:32px">Square format. Wings arch upward, eye in center body, head above, fanned tail below.</p>

<!-- ─── V4: Solid wings, dominant eye, short head ── -->
<h2>V4 — Solid wing mass · comb feathers · enlarged eye · compact head</h2>
<div class="row">

  <!-- 120px — full detail -->
  <div class="swatch">
    <svg width="120" height="120" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
      <!-- Left wing: solid mass with 4 comb feathers at tip -->
      <path d="M42,52 C30,44 18,32 12,24 L6,12 L12,22 L5,26 L11,34 L4,38 L10,46 C18,56 30,62 42,64Z" fill="#4F46E5"/>
      <!-- Right wing: mirror -->
      <path d="M58,52 C70,44 82,32 88,24 L94,12 L88,22 L95,26 L89,34 L96,38 L90,46 C82,56 70,62 58,64Z" fill="#4F46E5"/>
      <!-- Head: wide, flat, condor-like -->
      <ellipse cx="50" cy="22" rx="10" ry="8" fill="#4F46E5"/>
      <!-- Neck/upper torso -->
      <path d="M43,29 Q50,26 57,29 L58,50 Q50,47 42,50Z" fill="#4F46E5"/>
      <!-- Eye body: large dominant almond -->
      <path d="M30,57 Q50,40 70,57 Q50,74 30,57Z" fill="#4F46E5"/>
      <!-- Sclera -->
      <ellipse cx="50" cy="57" rx="15" ry="11" fill="white"/>
      <!-- Iris -->
      <circle cx="50" cy="57" r="8.5" fill="#4F46E5"/>
      <!-- Pupil -->
      <circle cx="50" cy="58" r="4.5" fill="#1e1b4b"/>
      <!-- Catchlight -->
      <circle cx="53" cy="54" r="2" fill="white"/>
      <!-- Tail: wide fan of 6 feathers -->
      <path d="M43,72 L34,92 L41,83 L47,90 L50,85 L53,90 L59,83 L66,92 L57,72Z" fill="#4F46E5"/>
    </svg>
    <label>120px</label>
  </div>

  <!-- 64px -->
  <div class="swatch">
    <svg width="64" height="64" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
      <path d="M42,52 C30,44 18,32 12,24 L6,12 L12,22 L5,26 L11,34 L4,38 L10,46 C18,56 30,62 42,64Z" fill="#4F46E5"/>
      <path d="M58,52 C70,44 82,32 88,24 L94,12 L88,22 L95,26 L89,34 L96,38 L90,46 C82,56 70,62 58,64Z" fill="#4F46E5"/>
      <ellipse cx="50" cy="22" rx="10" ry="8" fill="#4F46E5"/>
      <path d="M43,29 Q50,26 57,29 L58,50 Q50,47 42,50Z" fill="#4F46E5"/>
      <path d="M30,57 Q50,40 70,57 Q50,74 30,57Z" fill="#4F46E5"/>
      <ellipse cx="50" cy="57" rx="15" ry="11" fill="white"/>
      <circle cx="50" cy="57" r="8.5" fill="#4F46E5"/>
      <circle cx="50" cy="58" r="4.5" fill="#1e1b4b"/>
      <circle cx="53" cy="54" r="2" fill="white"/>
      <path d="M43,72 L34,92 L41,83 L47,90 L50,85 L53,90 L59,83 L66,92 L57,72Z" fill="#4F46E5"/>
    </svg>
    <label>64px</label>
  </div>

  <!-- 40px -->
  <div class="swatch">
    <svg width="40" height="40" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
      <path d="M42,52 C30,44 18,32 12,24 L6,12 L12,22 L5,26 L11,34 L4,38 L10,46 C18,56 30,62 42,64Z" fill="#4F46E5"/>
      <path d="M58,52 C70,44 82,32 88,24 L94,12 L88,22 L95,26 L89,34 L96,38 L90,46 C82,56 70,62 58,64Z" fill="#4F46E5"/>
      <ellipse cx="50" cy="22" rx="10" ry="8" fill="#4F46E5"/>
      <path d="M43,29 Q50,26 57,29 L58,50 Q50,47 42,50Z" fill="#4F46E5"/>
      <path d="M30,57 Q50,40 70,57 Q50,74 30,57Z" fill="#4F46E5"/>
      <ellipse cx="50" cy="57" rx="15" ry="11" fill="white"/>
      <circle cx="50" cy="57" r="8.5" fill="#4F46E5"/>
      <circle cx="50" cy="58" r="4.5" fill="#1e1b4b"/>
      <circle cx="53" cy="54" r="2" fill="white"/>
      <path d="M43,72 L34,92 L41,83 L47,90 L50,85 L53,90 L59,83 L66,92 L57,72Z" fill="#4F46E5"/>
    </svg>
    <label>40px</label>
  </div>

  <!-- 24px -->
  <div class="swatch">
    <svg width="24" height="24" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
      <path d="M42,52 C30,44 18,32 12,24 L6,12 L12,22 L5,26 L11,34 L4,38 L10,46 C18,56 30,62 42,64Z" fill="#4F46E5"/>
      <path d="M58,52 C70,44 82,32 88,24 L94,12 L88,22 L95,26 L89,34 L96,38 L90,46 C82,56 70,62 58,64Z" fill="#4F46E5"/>
      <ellipse cx="50" cy="22" rx="10" ry="8" fill="#4F46E5"/>
      <path d="M43,29 Q50,26 57,29 L58,50 Q50,47 42,50Z" fill="#4F46E5"/>
      <path d="M30,57 Q50,40 70,57 Q50,74 30,57Z" fill="#4F46E5"/>
      <ellipse cx="50" cy="57" rx="15" ry="11" fill="white"/>
      <circle cx="50" cy="57" r="8.5" fill="#4F46E5"/>
      <circle cx="50" cy="58" r="4.5" fill="#1e1b4b"/>
      <path d="M43,72 L34,92 L41,83 L47,90 L50,85 L53,90 L59,83 L66,92 L57,72Z" fill="#4F46E5"/>
    </svg>
    <label>24px</label>
  </div>

  <!-- Dark bg -->
  <div class="swatch dark">
    <svg width="80" height="80" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
      <path d="M42,52 C30,44 18,32 12,24 L6,12 L12,22 L5,26 L11,34 L4,38 L10,46 C18,56 30,62 42,64Z" fill="#818cf8"/>
      <path d="M58,52 C70,44 82,32 88,24 L94,12 L88,22 L95,26 L89,34 L96,38 L90,46 C82,56 70,62 58,64Z" fill="#818cf8"/>
      <ellipse cx="50" cy="22" rx="10" ry="8" fill="#818cf8"/>
      <path d="M43,29 Q50,26 57,29 L58,50 Q50,47 42,50Z" fill="#818cf8"/>
      <path d="M30,57 Q50,40 70,57 Q50,74 30,57Z" fill="#818cf8"/>
      <ellipse cx="50" cy="57" rx="15" ry="11" fill="#1a1f2e"/>
      <circle cx="50" cy="57" r="8.5" fill="#818cf8"/>
      <circle cx="50" cy="58" r="4.5" fill="#c7d2fe"/>
      <circle cx="53" cy="54" r="2" fill="white"/>
      <path d="M43,72 L34,92 L41,83 L47,90 L50,85 L53,90 L59,83 L66,92 L57,72Z" fill="#818cf8"/>
    </svg>
    <label style="color:#aaa">dark bg</label>
  </div>

  <!-- Wordmark light -->
  <div class="swatch">
    <div class="wordmark">
      <svg width="38" height="38" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <path d="M42,52 C30,44 18,32 12,24 L6,12 L12,22 L5,26 L11,34 L4,38 L10,46 C18,56 30,62 42,64Z" fill="#4F46E5"/>
        <path d="M58,52 C70,44 82,32 88,24 L94,12 L88,22 L95,26 L89,34 L96,38 L90,46 C82,56 70,62 58,64Z" fill="#4F46E5"/>
        <ellipse cx="50" cy="22" rx="10" ry="8" fill="#4F46E5"/>
        <path d="M43,29 Q50,26 57,29 L58,50 Q50,47 42,50Z" fill="#4F46E5"/>
        <path d="M30,57 Q50,40 70,57 Q50,74 30,57Z" fill="#4F46E5"/>
        <ellipse cx="50" cy="57" rx="15" ry="11" fill="white"/>
        <circle cx="50" cy="57" r="8.5" fill="#4F46E5"/>
        <circle cx="50" cy="58" r="4.5" fill="#1e1b4b"/>
        <circle cx="53" cy="54" r="2" fill="white"/>
        <path d="M43,72 L34,92 L41,83 L47,90 L50,85 L53,90 L59,83 L66,92 L57,72Z" fill="#4F46E5"/>
      </svg>
      MCPCondor
    </div>
    <label>wordmark</label>
  </div>

  <!-- Wordmark dark -->
  <div class="swatch dark">
    <div class="wordmark-dark">
      <svg width="38" height="38" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <path d="M42,52 C30,44 18,32 12,24 L6,12 L12,22 L5,26 L11,34 L4,38 L10,46 C18,56 30,62 42,64Z" fill="#818cf8"/>
        <path d="M58,52 C70,44 82,32 88,24 L94,12 L88,22 L95,26 L89,34 L96,38 L90,46 C82,56 70,62 58,64Z" fill="#818cf8"/>
        <ellipse cx="50" cy="22" rx="10" ry="8" fill="#818cf8"/>
        <path d="M43,29 Q50,26 57,29 L58,50 Q50,47 42,50Z" fill="#818cf8"/>
        <path d="M30,57 Q50,40 70,57 Q50,74 30,57Z" fill="#818cf8"/>
        <ellipse cx="50" cy="57" rx="15" ry="11" fill="#1a1f2e"/>
        <circle cx="50" cy="57" r="8.5" fill="#818cf8"/>
        <circle cx="50" cy="58" r="4.5" fill="#c7d2fe"/>
        <circle cx="53" cy="54" r="2" fill="white"/>
        <path d="M43,72 L34,92 L41,83 L47,90 L50,85 L53,90 L59,83 L66,92 L57,72Z" fill="#818cf8"/>
      </svg>
      MCPCondor
    </div>
    <label style="color:#aaa">wordmark dark</label>
  </div>

</div>

</body>
</html>"##.to_string())
}

async fn page_icons() -> Html<String> {
    Html(r##"<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Icon Options</title>
  <link rel="stylesheet" href="/assets/daisyui.css">
  <script src="/assets/tailwind.js"></script>
</head>
<body class="bg-base-200 p-10">
  <h1 class="text-2xl font-bold mb-2">Icon candidates</h1>
  <p class="text-base-content/60 text-sm mb-8">All at 3 sizes: 24px (navbar), 40px (login card), 64px (large). Click theme toggle to check dark mode.</p>
  <button onclick="document.documentElement.setAttribute('data-theme', document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark')" class="btn btn-sm mb-8">Toggle dark</button>

  <div class="grid grid-cols-2 md:grid-cols-3 gap-6">

    <!-- 1. Current condor (two wings) -->
    <div class="card bg-base-100 shadow p-5 flex flex-col gap-4">
      <div class="font-semibold text-sm">1. Condor (current)</div>
      <div class="flex items-end gap-4">
        <svg class="text-primary" width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8.5c-1.3 0-2.6.4-3.7 1.2L1.5 13l5.5-.5 2.8-1.9C10.6 10 11.3 9.7 12 9.7s1.4.3 2.2.9l2.8 1.9 5.5.5-6.8-3.3C14.6 8.9 13.3 8.5 12 8.5z"/><path d="M12 13c-.8 0-1.5.3-2.1.7L4.5 18l4.8-.9 2-1.4c.4-.3.8-.4 1.2-.4s.8.1 1.2.4l2 1.4 4.8.9-5.4-4.3C13.5 13.3 12.8 13 12 13z"/></svg>
        <svg class="text-primary" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8.5c-1.3 0-2.6.4-3.7 1.2L1.5 13l5.5-.5 2.8-1.9C10.6 10 11.3 9.7 12 9.7s1.4.3 2.2.9l2.8 1.9 5.5.5-6.8-3.3C14.6 8.9 13.3 8.5 12 8.5z"/><path d="M12 13c-.8 0-1.5.3-2.1.7L4.5 18l4.8-.9 2-1.4c.4-.3.8-.4 1.2-.4s.8.1 1.2.4l2 1.4 4.8.9-5.4-4.3C13.5 13.3 12.8 13 12 13z"/></svg>
        <svg class="text-primary" width="64" height="64" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8.5c-1.3 0-2.6.4-3.7 1.2L1.5 13l5.5-.5 2.8-1.9C10.6 10 11.3 9.7 12 9.7s1.4.3 2.2.9l2.8 1.9 5.5.5-6.8-3.3C14.6 8.9 13.3 8.5 12 8.5z"/><path d="M12 13c-.8 0-1.5.3-2.1.7L4.5 18l4.8-.9 2-1.4c.4-.3.8-.4 1.2-.4s.8.1 1.2.4l2 1.4 4.8.9-5.4-4.3C13.5 13.3 12.8 13 12 13z"/></svg>
      </div>
    </div>

    <!-- 2. Eye (surveillance) -->
    <div class="card bg-base-100 shadow p-5 flex flex-col gap-4">
      <div class="font-semibold text-sm">2. Eye (surveillance)</div>
      <div class="flex items-end gap-4">
        <svg class="text-primary" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
        <svg class="text-primary" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
        <svg class="text-primary" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
      </div>
    </div>

    <!-- 3. Eye with wings -->
    <div class="card bg-base-100 shadow p-5 flex flex-col gap-4">
      <div class="font-semibold text-sm">3. Winged eye (condor + surveillance)</div>
      <div class="flex items-end gap-4">
        <svg class="text-primary" width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 9.5c-1.2 0-2.5.4-3.5 1L1 14l5-.4 2.5-1.5C9.4 11.4 10.6 11 12 11s2.6.4 3.5 1.1l2.5 1.5L23 14l-7.5-3.5C14.5 9.9 13.2 9.5 12 9.5z"/><ellipse cx="12" cy="13" rx="2.2" ry="1.5"/><circle cx="12" cy="13" r="0.9" fill="white"/></svg>
        <svg class="text-primary" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M12 9.5c-1.2 0-2.5.4-3.5 1L1 14l5-.4 2.5-1.5C9.4 11.4 10.6 11 12 11s2.6.4 3.5 1.1l2.5 1.5L23 14l-7.5-3.5C14.5 9.9 13.2 9.5 12 9.5z"/><ellipse cx="12" cy="13" rx="2.2" ry="1.5"/><circle cx="12" cy="13" r="0.9" fill="white"/></svg>
        <svg class="text-primary" width="64" height="64" viewBox="0 0 24 24" fill="currentColor"><path d="M12 9.5c-1.2 0-2.5.4-3.5 1L1 14l5-.4 2.5-1.5C9.4 11.4 10.6 11 12 11s2.6.4 3.5 1.1l2.5 1.5L23 14l-7.5-3.5C14.5 9.9 13.2 9.5 12 9.5z"/><ellipse cx="12" cy="13" rx="2.2" ry="1.5"/><circle cx="12" cy="13" r="0.9" fill="white"/></svg>
      </div>
    </div>

    <!-- 4. Condor silhouette (improved - top-down view) -->
    <div class="card bg-base-100 shadow p-5 flex flex-col gap-4">
      <div class="font-semibold text-sm">4. Condor silhouette (top-down)</div>
      <div class="flex items-end gap-4">
        <svg class="text-primary" width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 6c-.6 0-1.1.1-1.6.4L2 11l4.5.3 3-1.8C10.4 9 11.2 8.8 12 8.8s1.6.2 2.5.7l3 1.8L22 11l-8.4-4.6C13.1 6.1 12.6 6 12 6z"/><path d="M12 11c-.6 0-1.2.2-1.7.5L5 15l4 .2 2-1.3c.5-.3.9-.4 1-.4s.5.1 1 .4l2 1.3 4-.2-5.3-3.5C13.2 11.2 12.6 11 12 11z"/><ellipse cx="12" cy="17.5" rx="1.5" ry="2" /></svg>
        <svg class="text-primary" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M12 6c-.6 0-1.1.1-1.6.4L2 11l4.5.3 3-1.8C10.4 9 11.2 8.8 12 8.8s1.6.2 2.5.7l3 1.8L22 11l-8.4-4.6C13.1 6.1 12.6 6 12 6z"/><path d="M12 11c-.6 0-1.2.2-1.7.5L5 15l4 .2 2-1.3c.5-.3.9-.4 1-.4s.5.1 1 .4l2 1.3 4-.2-5.3-3.5C13.2 11.2 12.6 11 12 11z"/><ellipse cx="12" cy="17.5" rx="1.5" ry="2" /></svg>
        <svg class="text-primary" width="64" height="64" viewBox="0 0 24 24" fill="currentColor"><path d="M12 6c-.6 0-1.1.1-1.6.4L2 11l4.5.3 3-1.8C10.4 9 11.2 8.8 12 8.8s1.6.2 2.5.7l3 1.8L22 11l-8.4-4.6C13.1 6.1 12.6 6 12 6z"/><path d="M12 11c-.6 0-1.2.2-1.7.5L5 15l4 .2 2-1.3c.5-.3.9-.4 1-.4s.5.1 1 .4l2 1.3 4-.2-5.3-3.5C13.2 11.2 12.6 11 12 11z"/><ellipse cx="12" cy="17.5" rx="1.5" ry="2" /></svg>
      </div>
    </div>

    <!-- 5. Radar / signal waves -->
    <div class="card bg-base-100 shadow p-5 flex flex-col gap-4">
      <div class="font-semibold text-sm">5. Radar (monitoring)</div>
      <div class="flex items-end gap-4">
        <svg class="text-primary" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 12 L19 5"/><circle cx="12" cy="12" r="2" fill="currentColor" stroke="none"/><path d="M6.3 17.7a8 8 0 010-11.4"/><path d="M3.5 20.5a12 12 0 010-17"/><path d="M17.7 6.3a8 8 0 010 11.4"/></svg>
        <svg class="text-primary" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 12 L19 5"/><circle cx="12" cy="12" r="2" fill="currentColor" stroke="none"/><path d="M6.3 17.7a8 8 0 010-11.4"/><path d="M3.5 20.5a12 12 0 010-17"/><path d="M17.7 6.3a8 8 0 010 11.4"/></svg>
        <svg class="text-primary" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 12 L19 5"/><circle cx="12" cy="12" r="2" fill="currentColor" stroke="none"/><path d="M6.3 17.7a8 8 0 010-11.4"/><path d="M3.5 20.5a12 12 0 010-17"/><path d="M17.7 6.3a8 8 0 010 11.4"/></svg>
      </div>
    </div>

    <!-- 6. Telescope / binoculars -->
    <div class="card bg-base-100 shadow p-5 flex flex-col gap-4">
      <div class="font-semibold text-sm">6. Binoculars (observe)</div>
      <div class="flex items-end gap-4">
        <svg class="text-primary" width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H7L4 11v4a3 3 0 006 0v-4L7.5 7H10V4zM17 4h-3v3h2.5L14 11v4a3 3 0 006 0v-4l-3-7zM10 11h4"/></svg>
        <svg class="text-primary" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H7L4 11v4a3 3 0 006 0v-4L7.5 7H10V4zM17 4h-3v3h2.5L14 11v4a3 3 0 006 0v-4l-3-7zM10 11h4"/></svg>
        <svg class="text-primary" width="64" height="64" viewBox="0 0 24 24" fill="currentColor"><path d="M10 4H7L4 11v4a3 3 0 006 0v-4L7.5 7H10V4zM17 4h-3v3h2.5L14 11v4a3 3 0 006 0v-4l-3-7zM10 11h4"/></svg>
      </div>
    </div>

  </div>
</body>
</html>"##.to_string())
}

async fn static_asset(Path(path): Path<String>) -> Response {
    match StaticAssets::get(&path) {
        Some(content) => {
            let mime = match path.rsplit('.').next().unwrap_or("") {
                "css"  => "text/css",
                "js"   => "application/javascript",
                "svg"  => "image/svg+xml",
                "png"  => "image/png",
                "ico"  => "image/x-icon",
                _      => "application/octet-stream",
            };
            ([(header::CONTENT_TYPE, mime)], content.data.into_owned()).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        // root and bare paths (direct browser access)
        .route("/", get(page_dashboard))
        .route("/login", get(page_login))
        .route("/login/error", get(page_login_err))
        .route("/dashboard", get(page_dashboard))
        .route("/integrations", get(page_integrations))
        .route("/agents", get(page_agents))
        .route("/profiles", get(page_profiles))
        .route("/audit", get(page_audit))
        .route("/profiles/p2", get(page_profile_detail))
        .route("/agents/a1", get(page_agent_detail))
        .route("/integrations/1/tools", get(page_integration_tools))
        // /ui/* paths — mirrors production routing so template links work
        .route("/ui", get(page_dashboard))
        .route("/ui/login", get(page_login))
        .route("/ui/dashboard", get(page_dashboard))
        .route("/ui/integrations", get(page_integrations))
        .route("/ui/agents", get(page_agents))
        .route("/ui/profiles", get(page_profiles))
        .route("/ui/audit", get(page_audit))
        .route("/ui/profiles/p2", get(page_profile_detail))
        .route("/ui/profiles/{_id}", get(page_profile_detail))
        .route("/ui/agents/a1", get(page_agent_detail))
        .route("/ui/agents/{_id}", get(page_agent_detail))
        .route("/ui/integrations/1/tools", get(page_integration_tools))
        .route("/ui/integrations/{_id}/tools", get(page_integration_tools))
        .route("/icons", get(page_icons))
        .route("/logo", get(page_logo))
        .route("/assets/{*path}", get(static_asset));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await.unwrap();
    println!("Preview server running on http://127.0.0.1:3001");
    axum::serve(listener, app).await.unwrap();
}
