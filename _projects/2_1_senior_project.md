---
layout: project
title: "RootView (blogs)"
description: "KVM-based eBPF detection toolkit and detection engine"
project_tag: ctfs
---

### Intro

This is my senior project worked alongside Braiden Ames, Dominick Morales, and Dylin Irons.

The name was inspired by [elbee's ropview](https://github.com/elbee-cyber/RopView)

Here is the [source](https://github.com/papichulo16/rootview).

### Blogs
<div class="writeup-list">
  {% assign writeup_posts = site.blogs | where_exp: "post", "post.tags contains 'rootview'" | sort: "date" | reverse %}

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

