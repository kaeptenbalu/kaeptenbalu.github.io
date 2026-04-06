---
title: "RSS Feed Test - Please Ignore 🧪"
date: 2026-04-06
author: "Manuel Boll"
tags: ["test"]
---

## This is a Test Post

This post exists solely to verify that the RSS feed updates automatically when new content is published.

**What we're testing:**
- Automatic feed generation via Hugo
- GitHub Actions build pipeline
- RSS feed propagation to readers

**Expected behavior:**
1. This post appears in the RSS feed at `https://www.mboll.eu/feed.xml`
2. RSS readers pick up the update within 15-60 minutes
3. The W3C validator continues to show the feed as valid

---

### Technical Details

The RSS feed is configured in `hugo.toml` to:
- Output to `feed.xml` instead of the default `index.xml`
- Include the last 20 posts
- Use proper atom:link self-reference

This post will be deleted immediately after verification. If you're reading this in an RSS reader, the test worked! 🎉

```bash
# To verify the feed manually:
curl -s https://www.mboll.eu/feed.xml | grep "RSS Feed Test"
```

---

**Status:** This is a temporary test post and will be removed shortly.
