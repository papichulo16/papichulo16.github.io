---
layout: project
title: "pKVMI-Mod (blogs)"
description: "Adding VMI to pKVM with EL2 vendor modules"
project_tag: ctfs
---

### Intro

Adding VMI to pKVM with EL2 vendor modules

Here is the [source](https://github.com/papichulo16/pkvmi-mod).

### Blogs
<div class="writeup-list">
  {% assign writeup_posts = site.blogs | where_exp: "post", "post.tags contains 'pkvmi'" | sort: "date" | reverse %}

  {% for post in writeup_posts %}
  <a href="{{ post.url }}" class="writeup-card">
    <div>
      <h2>{{ post.title }}</h2>
      <p class="date">{{ post.date | date: "%B %d, %Y" }}</p>
      <p class="description">{{ post.description }}</p>
    </div>
  </a>
  {% endfor %}
</div>

