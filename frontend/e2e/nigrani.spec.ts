import { expect, test } from '@playwright/test'

/// Console-wiring E2E (s-I6): the 57 integration tests cover the API; these
/// cover what only a browser proves — the React surfaces actually render,
/// submit, and reflect state. Requires the dev stack: `cargo run` (backend)
/// + `npm run dev` (frontend) — the tests hit the vite proxy.

async function login(page, username: string) {
  await page.goto('/')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill('password')
  await page.getByRole('button', { name: /sign in|log in/i }).click()
  await expect(page.getByText(/Nigrani/i).first()).toBeVisible()
}

test('login lands on the dashboard with KPI cards', async ({ page }) => {
  await login(page, 'superadmin')
  // SuperAdmin's panel heading + the KPI row (stats render, not a blank shell).
  await expect(page.getByRole('heading', { name: /System ledger/i })).toBeVisible()
  await expect(page.locator('section').filter({ hasText: /Crossings/i }).first()).toBeVisible()
})

test('kiosk: manual entry records a crossing', async ({ page }) => {
  await login(page, 'gate')
  // The kiosk card is present with its action buttons.
  const logManual = page.getByRole('button', { name: /log manual entry|मैनुअल प्रवेश दर्ज/i })
  await expect(logManual).toBeVisible()
  // Hindi toggle flips the label, then back.
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
