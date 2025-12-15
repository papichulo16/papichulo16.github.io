---
layout: project
title: "PWN Writeups (blogs)"
description: "Writeups from interesting CTF challenges"
project_tag: ctfs
---

When doing CTFs I like to make writeups for challenges that I find to be interesting and cool. Here are some of them. Also here is a link to the [source code](https://www.github.com/papichulo16/ctf-stuff/)

<div class="writeup-list">
  {% assign writeup_posts = site.blogs | where_exp: "post", "post.tags contains 'ctf'" | sort: "date" | reverse %}

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


