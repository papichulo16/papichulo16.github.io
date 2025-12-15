---
layout: default
title: "Blogs"
permalink: /blogs/
---

# Blogs 

<div class="writeup-list">
  {% assign writeup_posts = site.blogs | sort: "date" | reverse %}

  {% for post in writeup_posts %}
  <a href="{{ post.url }}" class="writeup-card">
    <div>
      <h2>{{ post.title }} ({{ post.tags }} blog)</h2>
      <p class="date">{{ post.date | date: "%B %d, %Y" }}</p>
      <p class="description">{{ post.description }}</p>
    </div>
  </a>
  {% endfor %}
</div>


