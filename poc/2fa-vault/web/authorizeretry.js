export function createAuthorizeRetryState() {
  let pending = null;
  let completed = null;

  return Object.freeze({
    stage(reviewKey, body, validation, challengeHex) {
      requireReviewKey(reviewKey);
      if (!body || typeof body !== "object") throw new Error("authorize retry body");
      if (!validation || typeof validation !== "object") throw new Error("authorize retry validation");
      requireChallenge(challengeHex);
      const bodyJSON = JSON.stringify(body);
      if (!bodyJSON) throw new Error("authorize retry body");
      pending = Object.freeze({
        reviewKey,
        bodyJSON,
        validation: Object.freeze({ ...validation }),
        challengeHex,
      });
      completed = null;
      return pending;
    },

    pendingFor(reviewKey) {
      if (!sameReview(pending, reviewKey)) return null;
      return pending;
    },

    markAuthorized(reviewKey, receipt) {
      if (!sameReview(pending, reviewKey)) throw new Error("authorize retry state mismatch");
      if (!receipt || typeof receipt !== "object") throw new Error("authorize retry receipt");
      requireChallenge(receipt.challengeHex);
      if (!/^[0-9a-f]{64}$/.test(String(receipt.expectedTxid || ""))) {
        throw new Error("authorize retry transaction id");
      }
      completed = Object.freeze({
        reviewKey,
        challengeHex: receipt.challengeHex,
        expectedTxid: receipt.expectedTxid,
        replay: receipt.replay === true,
      });
      // Drop the exact PSBT and WebAuthn assertion body as soon as the
      // successful response has been independently verified.
      pending = null;
      return completed;
    },

    completedFor(reviewKey) {
      if (!sameReview(completed, reviewKey)) return null;
      return completed;
    },

    clearUnless(reviewKey) {
      requireReviewKey(reviewKey);
      if ((pending && pending.reviewKey !== reviewKey) ||
          (completed && completed.reviewKey !== reviewKey)) {
        pending = null;
        completed = null;
        return true;
      }
      return false;
    },

    clear() {
      pending = null;
      completed = null;
    },
  });
}

function sameReview(entry, reviewKey) {
  requireReviewKey(reviewKey);
  return entry?.reviewKey === reviewKey;
}

function requireReviewKey(value) {
  if (typeof value !== "string" || value.length === 0) throw new Error("authorize retry review key");
}

function requireChallenge(value) {
  if (!/^[0-9a-f]{64}$/.test(String(value || ""))) throw new Error("authorize retry challenge");
}
