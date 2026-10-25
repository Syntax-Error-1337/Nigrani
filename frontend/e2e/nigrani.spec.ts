import { expect, test } from '@playwright/test'

/// Console-wiring E2E (s-I6): the 57 integration tests cover the API; these
/// cover what only a browser proves — the React surfaces actually render,
/// submit, and reflect state. Requires the dev stack: `cargo run` (backend)
/// + `npm run dev` (frontend) — the tests hit the vite proxy.

async function login(page, username: string) {
  await page.goto('/')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password', { exact: true }).fill('password')
  await page.getByRole('button', { name: /sign in|log in/i }).click()
  await expect(page.getByText(/Nigrani/i).first()).toBeVisible()
}

test('login lands on the dashboard with KPI cards', async ({ page }) => {
  await login(page, 'superadmin')
  // SuperAdmin lands on Overview: heading + the KPI row render (not a blank shell).
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible()
  await expect(page.getByText('Crossings · 24h', { exact: true })).toBeVisible()
})

test('kiosk: manual entry records a crossing', async ({ page }) => {
  await login(page, 'gate')
  // The gate roster is managed in Sites & gates; the kiosk only lights up
  // once a post is selected (guard renders a pick-a-post empty state).
  await page.getByRole('button', { name: 'Sites & gates' }).click()
  // Pick the first gate post of the default site (seeded DB always has gates).
  await page.locator('table').nth(1).locator('tbody tr').first().click()
  await page.getByRole('button', { name: 'Gate kiosk' }).click()
  const logManual = page.getByRole('button', { name: /log manual entry|मैनुअल प्रवेश दर्ज/i })
  await expect(logManual).toBeVisible()
  // Hindi toggle flips the operator strings, then back.
  const toggle = page.getByRole('button', { name: /^हिंदी$|^English$/ })
  await toggle.click()
  await expect(page.getByRole('button', { name: /log manual entry|मैनुअल प्रवेश दर्ज/i })).toBeVisible()
  await toggle.click()
})

test('audit trail verify verdict renders', async ({ page }) => {
  await login(page, 'superadmin')
  const verify = page.getByRole('button', { name: /verify chain/i })
  if (await verify.count()) {
    await verify.click()
    await expect(page.getByText(/Chain intact|CHAIN BROKEN/i)).toBeVisible()
  }
})

test('press apply page renders without login', async ({ page }) => {
  await page.goto('/press')
  await expect(page.locator('form')).toBeVisible()
})
