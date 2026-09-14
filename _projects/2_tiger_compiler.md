---
layout: project
title: "Tiger Compiler (blogs)"
description: "Compiler from scratch following the \"Modern Compiler Implementation in C\" book "
project_tag: ctfs
---

### Intro

Basically what the description says, I followed the "Modern Compiler Implementation in C" book and had some fun with it. 

Here is the [source](https://github.com/papichulo16/tiger-compiler).

### Blogs
<div class="writeup-list">
  {% assign writeup_posts = site.blogs | where_exp: "post", "post.tags contains 'compiler'" | sort: "date" | reverse %}

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

