# The ConsequenceOS site

The project page and the Agent Cards, served at `https://consequenceos.emmanelsobowale.dev`. It's static: no build step.

- `index.html`: the project page.
- `agents/`: the Agent Cards of agents registered in Concordium's Agent Registry, and an index of them.
- `vercel.json`: headers. The cards can be fetched from any origin, and are cached for five minutes.

## Deploying

The site is a Vercel project on this repository:

1. In Vercel, **Add New → Project**, and import `Matutozi/Consequence-OS`.
2. Set **Root Directory** to `site`. Leave the framework as **Other** and the build command empty.
3. Deploy. Then, in the project's **Settings → Domains**, add `consequenceos.emmanelsobowale.dev`.

Each push to `main` redeploys it. To redeploy only when `site/` changes, set **Settings → Git → Ignored Build Step** to `git diff --quiet HEAD^ HEAD -- .`.

## Adding an Agent Card

The registry pins a card's URL and SHA-256, so the file must be hosted exactly as `consequence-anchor card` wrote it: don't edit, reformat or pretty-print it.

For the Concordium demo:

```bash
export CONCORDIUM_ACCOUNT=~/my-account.export
CARD_URL=https://consequenceos.emmanelsobowale.dev/agents/refund-bot.json scripts/demo-concordium.sh setup
```

When `setup` stops and asks you to host the card:

```bash
cp ~/.consequence/concordium-demo/agent-card.json site/agents/refund-bot.json
git add site/agents/refund-bot.json && git commit -m "Host the demo agent's card" && git push
```

Wait for the deploy, and check the hosted file is the same, byte for byte:

```bash
curl -fsS https://consequenceos.emmanelsobowale.dev/agents/refund-bot.json | sha256sum
sha256sum ~/.consequence/concordium-demo/agent-card.json
```

When the two match, press Enter in `setup` to pin the card. For another agent, use its own file name, and add it to `agents/index.html`.
