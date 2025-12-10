---
layout: default
title: "Projects"
permalink: /projects/
---

# Projects

<div class="projects-grid">
{% for p in site.projects %}
  <a class="project-card" href="{{ p.url }}">
    <h3>{{ p.title }}</h3>
    <p>{{ p.description }}</p>
  </a>
{% endfor %}
</div>

