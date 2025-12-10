---
layout: project
title: "Magical Kernel"
description: "Hobby kernel made from scratch"
project_tag: ctfs
---

<ul>
{% assign posts = site.posts | where: "project", page.project_tag %}
{% for post in posts %}
  <li>
    <a href="{{ post.url }}">{{ post.title }}</a> — {{ post.date | date: "%B %d, %Y" }}
  </li>
{% endfor %}
</ul>

[source](https://www.github.com/papichulo16/magical-kernel/)

