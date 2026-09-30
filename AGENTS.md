# pytempo

## Changelogs

Always add a `.changelog/<descriptive-name>.md` fragment with each change. Include it in the same pull request; changelog entries are not generated automatically for pull requests.

Use `changelogs add` or create the file directly with YAML frontmatter:

```md
---
pytempo: patch
---

Fixed a description of the changed behavior.
```

Choose the appropriate version bump and describe the change in past tense (for example, "Added support for …" or "Fixed parsing of …").

Never edit `CHANGELOG.md` manually. The release workflow generates it from these fragments when versioning the package.
