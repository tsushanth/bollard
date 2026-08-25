// SPDX-License-Identifier: Apache-2.0
//
// A hand-curated corpus of realistic legitimate hostnames, spanning the
// categories most likely to produce a false positive on the entropy test —
// especially hash-like CDN/cloud-storage/SaaS subdomains, which are exactly
// the shape a naive "high entropy = suspicious" heuristic gets wrong.
//
// HONEST LIMITS: this is a hand-built list of realistic, publicly-known
// domain *patterns* (~110 entries), not a captured production traffic
// sample. It exists to give a new deployment a safer default before it has
// accumulated its own real BOLLARD_BASELINE_MODE traffic, and to stress-test
// the threshold against the categories most likely to break it. It is NOT a
// substitute for calibrating against a real deployment's own baseline log
// once one exists — `calibrate_from_hosts` accepts real hostnames from a
// baseline log specifically so this corpus can be blended with, or replaced
// by, real data.

pub const LEGIT_HOSTNAMES: &[&str] = &[
    // major sites / mail / auth
    "google.com", "www.google.com", "mail.google.com", "accounts.google.com",
    "drive.google.com", "docs.google.com", "calendar.google.com",
    "github.com", "api.github.com", "raw.githubusercontent.com", "codeload.github.com",
    "microsoft.com", "login.microsoftonline.com", "outlook.office365.com", "graph.microsoft.com",
    "apple.com", "icloud.com", "appleid.apple.com",
    "amazon.com", "aws.amazon.com", "console.aws.amazon.com",
    "facebook.com", "graph.facebook.com", "connect.facebook.net",
    "twitter.com", "api.twitter.com", "x.com",
    "linkedin.com", "api.linkedin.com",
    "stripe.com", "api.stripe.com", "js.stripe.com",
    "slack.com", "api.slack.com", "hooks.slack.com",
    "zoom.us", "api.zoom.us",
    "dropbox.com", "api.dropbox.com", "content.dropboxapi.com",
    "salesforce.com", "my.salesforce.com", "login.salesforce.com",
    "atlassian.com", "api.atlassian.com", "id.atlassian.com",
    "cloudflare.com", "api.cloudflare.com", "1.1.1.1",
    "npmjs.com", "registry.npmjs.org",
    "pypi.org", "files.pythonhosted.org",
    "docker.io", "hub.docker.com", "registry-1.docker.io",
    "openai.com", "api.openai.com",
    "anthropic.com", "api.anthropic.com",
    "twilio.com", "api.twilio.com",
    "sendgrid.com", "api.sendgrid.com",
    "datadoghq.com", "api.datadoghq.com",
    "sentry.io", "o12345.ingest.sentry.io",
    "segment.com", "api.segment.io",
    "intercom.io", "api.intercom.io",
    "mixpanel.com", "api.mixpanel.com",
    "amplitude.com", "api2.amplitude.com",
    "notion.so", "api.notion.com",
    "figma.com", "api.figma.com",
    "airtable.com", "api.airtable.com",
    "zendesk.com", "acmecorp.zendesk.com",
    "shopify.com", "acmestore.myshopify.com",
    // hash-like CDN edge nodes -- the highest-risk false-positive category
    "d2j6dbq0eux0bg.cloudfront.net",
    "d1a2b3c4d5e6f7g.cloudfront.net",
    "d3fenhy8801fjk.cloudfront.net",
    "e6858.dsw2.akamaiedge.net",
    "a1887.dscb.akamai.net",
    "fastly.net", "prod.map.fastly.net",
    "x.ss2.us.fastly.net",
    "cdn77.org", "1234.rsc.cdn77.org",
    "b-cdn.net", "acmeapp.b-cdn.net",
    "azureedge.net", "acmeapp.azureedge.net",
    // cloud storage buckets -- often hash/account-id heavy
    "storage.googleapis.com",
    "acme-prod-us-east1-a1b2c3d4.storage.googleapis.com",
    "acme-app-prod-logs-a8f3e9c1.s3.amazonaws.com",
    "s3.amazonaws.com", "s3-us-west-2.amazonaws.com",
    "acmeappstorage9f3e1c.blob.core.windows.net",
    "abcd1234efgh5678ijkl.blob.core.windows.net",
    // ad-tech -- long multi-label domains, real known false-positive risk
    "doubleclick.net", "pubads.g.doubleclick.net", "stats.g.doubleclick.net",
    "googlesyndication.com", "pagead2.googlesyndication.com",
    "googletagmanager.com", "www.googletagmanager.com",
    "googletagservices.com",
    "amazon-adsystem.com", "aax.amazon-adsystem.com",
    "criteo.com", "static.criteo.net",
    "adnxs.com", "ib.adnxs.com",
    "rubiconproject.com", "fastlane.rubiconproject.com",
    "pubmatic.com", "hbopenbid.pubmatic.com",
    "openx.net", "rtb.openx.net",
    "taboola.com", "trc.taboola.com",
    "outbrain.com", "widgets.outbrain.com",
    "scorecardresearch.com", "sb.scorecardresearch.com",
    // SaaS multi-tenant subdomains -- sometimes hash/random-word based
    "acmecorp.atlassian.net",
    "acmecorp.slack.com",
    "still-shore-42817.herokuapp.com",
    "quiet-forest-38291.herokuapp.com",
    "acme-landing-page.vercel.app",
    "acme-storybook-git-main-acmecorp.vercel.app",
    "acme-docs.netlify.app",
    "63f2a9d1e8b7c4.ngrok.io",
    "acmeapp.herokudns.com",
];

/// Suggest an entropy threshold from a corpus of hostnames: the given
/// percentile of the corpus's entropy distribution, plus a safety margin.
/// Percentile (not max) so one unusually weird-but-legit hostname in a large
/// corpus doesn't single-handedly force the threshold too high to be useful.
pub fn calibrate_entropy_threshold(hostnames: &[String], percentile_p: f64, margin: f64) -> f64 {
    if hostnames.is_empty() {
        return f64::INFINITY; // no data: don't invent a number, refuse to threshold
    }
    let mut entropies: Vec<f64> = hostnames.iter().map(|h| crate::hostname_entropy(h)).collect();
    entropies.sort_by(f64::total_cmp);
    crate::percentile(&entropies, percentile_p) + margin
}

/// The default shipped with bollard-proxy: max (not a percentile) over the
/// curated corpus, plus a margin. Percentile-based calibration makes sense
/// once real, possibly-noisy baseline traffic is blended in (a handful of
/// odd real hosts shouldn't single-handedly force the threshold sky-high),
/// but the curated corpus was hand-picked specifically to contain the hard
/// cases with no accidental outliers to exclude -- so the safe default
/// clears all of it, not 99% of it. See the corpus test in
/// crates/bollard-anomaly/src/main.rs that checks this holds.
pub fn default_threshold() -> f64 {
    let hosts: Vec<String> = LEGIT_HOSTNAMES.iter().map(|s| s.to_string()).collect();
    calibrate_entropy_threshold(&hosts, 1.0, 0.15)
}
