---
name: anchorbrowser
description: 'Use this skill when the user needs web automation with the AnchorBrowser Python SDK (`anchorbrowser`): agent tasks, sessions, screenshots, fetch, Playwright-over-CDP, identities, and predefined tasks. Use when the user asks to navigate pages, extract data, fill forms, take screenshots, or run a cloud browser.'
---

# AnchorBrowser Python SDK

Use the [`anchorbrowser`](https://pypi.org/project/anchorbrowser/) PyPI package (v1+). Do **not** use the v0 client (`client.task.run`, `ANCHOR_*` inputs) — that is the legacy API.

Docs: [SDK reference](https://docs.anchorbrowser.io/sdk-reference/overview) · source: [AnchorBrowser-SDK-Python](https://github.com/anchorbrowser/AnchorBrowser-SDK-Python)

Requires Python 3.10+. Resources hang off a client instance. Path params are positional; query/body params are `snake_case` keyword arguments.

## Setup Check

```bash
echo "$ANCHORBROWSER_API_KEY"
```

Install the package if it is not already in the project:

```bash
pip install anchorbrowser
```

The SDK reads `ANCHORBROWSER_API_KEY` from the environment. Get a key at [app.anchorbrowser.io](https://app.anchorbrowser.io/api-keys). Set it explicitly only when needed:

```python
from anchorbrowser import Anchorbrowser

client = Anchorbrowser()  # reads ANCHORBROWSER_API_KEY
# client = Anchorbrowser(api_key="your-api-key")
```

For `async`/`await`, use `AsyncAnchorbrowser` with the same methods.

Run snippets with `python` (or a temp `.py` file). Execute — do not only describe the API.

## When To Use Which API

- **`client.agent.task`** — default for "go do this on the web" (navigate, extract, fill forms).
- **`client.tools`** — one-shot fetch / screenshot / PDF / perform_web_task.
- **`client.browser` / `client.sessions`** — multi-step Playwright control over a cloud session.
- **`client.identities` / `client.applications`** — stored logins attached to a session.
- **`client.tasks`** — run a predefined task ID with input params (v2). Prefer this over `client.tasks_legacy`.

## Agent task (default)

```python
from anchorbrowser import Anchorbrowser

client = Anchorbrowser()

result = client.agent.task(
    "Go to news.ycombinator.com and return the top 5 story titles",
    task_options={"url": "https://news.ycombinator.com"},
)
print(result.data.result)
```

Reuse an existing session with `session_id="..."`. Create a session with extra config via `session_options={...}` (do not pass both).

`client.agent.browser_task(...)` starts the same task but returns immediately with `session_id`, a `concurrent.futures.Future` (`task_result_task`), and a Playwright context manager (`playwright_browser`).

## Tools (one-shot)

```python
from anchorbrowser import Anchorbrowser

client = Anchorbrowser()

page = client.tools.fetch_webpage(url="https://example.com")
shot = client.tools.screenshot_webpage(url="https://example.com")
pdf = client.tools.create_page_pdf(url="https://example.com")
task = client.tools.perform_web_task(
    prompt="go to ycombinator hacker news and get top 10 news",
)
```

`screenshot_webpage` returns binary (`shot.read()`). Pass `session_id=` to screenshot an existing session instead of a URL.

## Session + Playwright

```python
from anchorbrowser import Anchorbrowser

client = Anchorbrowser()

session = client.sessions.create_session(
    session={"recording": {"active": True}},
)
with client.browser.connect(session.data.id) as browser:
    page = browser.contexts[0].pages[0]
    page.goto("https://example.com")
    print(page.title())
client.sessions.delete_session(session.data.id)
```

`with client.browser.create() as browser:` creates a session and connects in one step (no session id returned). Use `create_session` + `connect` when you need to delete or reuse the session.

OS-level session helpers (no Playwright) live on `client.sessions`: `goto`, mouse, keyboard, clipboard, screenshot, upload.

## Identities

```python
from anchorbrowser import Anchorbrowser

client = Anchorbrowser()

identity = client.identities.create_identity(source="https://app.example")
session = client.sessions.create_session(
    identities=[{"id": identity.data.id}],
)
```

## Predefined tasks

```python
from anchorbrowser import Anchorbrowser

client = Anchorbrowser()

run = client.tasks.run_task(
    "<task-id>",
    input_params={"query": "engineer"},
)
print(run.run_id, run.status)
```

Poll with `client.tasks.get_task_run_status(run.run_id)` until `status` is `success`, `failure`, `timeout`, or `cancelled`. To block until completion, pass `extra_body={"sync": True}`.

## Execution Expectations

- Execute the SDK call; return the result, not only sample code.
- Prefer `client.agent.task` unless the user needs a screenshot, PDF, raw fetch, or a Playwright loop.
- After creating a session, delete it when the task is done.
- If auth fails, check `ANCHORBROWSER_API_KEY` — do not fall back to the v0 client or raw HTTP.
