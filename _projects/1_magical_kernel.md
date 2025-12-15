---
layout: project
title: "Magical Kernel (blogs)"
description: "Hobby kernel made from scratch"
project_tag: ctfs
---

### Intro
I wanted to learn more about how operating systems work internally so I decided to make my own `64-bit x86_64 OS`. I only used the internet and AI to help me understand theoretical concepts and generate trivial pieces of code like scancode lookup tables. Outside of that all code was written by me so I could properly learn as much as possible. I also mainly used the book `Operating Systems Concepts: Three Easy Pieces` to also guide me a bit.

I decided to blog my process and below are the blogs. Also here is the [source](https://www.github.com/papichulo16/magical-kernel/).

### Blogs
<div class="writeup-list">
  {% assign writeup_posts = site.blogs | where_exp: "post", "post.tags contains 'kernel'" | sort: "date" | reverse %}

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

