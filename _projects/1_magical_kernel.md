---
layout: project
title: "Magical Kernel"
description: "Magical Kernel"
project_tag: ctfs
---

# {{ page.title }}

<ul>
{% assign posts = site.posts | where: "project", page.project_tag %}
{% for post in posts %}
  <li>
    <a href="{{ post.url }}">{{ post.title }}</a> — {{ post.date | date: "%B %d, %Y" }}
  </li>
{% endfor %}
</ul>

