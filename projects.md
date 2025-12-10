---
layout: default
title: Projects
---

# Projects

<ul>
{% for project in site.projects %}
  <li>
    <details>
      <summary><strong>{{ project.title }}</strong> — {{ project.description }}</summary>
      <ul>
      {% assign posts = site.posts | where: "project", project.project_tag %}
        {% for post in posts %}
          <li><a href="{{ post.url }}">{{ post.title }}</a></li>
        {% endfor %}
      </ul>
    </details>
  </li>
{% endfor %}
</ul>

