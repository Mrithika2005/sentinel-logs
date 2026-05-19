<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/68d14db7-dd5e-4a92-a8b7-5cad0c438ae5

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key

3. To enable ClickHouse persistence, also set these environment variables:
   - `CLICKHOUSE_HOST` (for example `http://localhost:8123`)
   - `CLICKHOUSE_DATABASE` (must already exist in ClickHouse)
   - `CLICKHOUSE_TABLE` (optional, default `sentinel_logs`)
   - `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD` if authentication is enabled

4. Run the app:
   `npm run dev`
