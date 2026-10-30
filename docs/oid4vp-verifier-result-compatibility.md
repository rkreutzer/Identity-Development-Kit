# OID4VP verifier results: compatibility note

This note is for readers of verified presentation results: the Universal OID4VP status API (`verified_data.credential_claims`) and the verifier's `MatchedCredential.disclosedClaims`.

## What changed for readers

1. **Text stays text.** A claim issued as the string `"0612345678"` is reported as that string. It is no longer turned into the number `612345678`, and `"true"` is no longer turned into a boolean.
2. **Nested values are kept.** Objects and arrays are reported as JSON objects and arrays at every depth. They are no longer flattened to their text form.
3. **mdoc values follow RFC 8949 section 6.1.** Integers, floats, booleans, text, arrays and maps keep their JSON type. Byte strings are reported as unpadded base64url text. Date and time tags are reported as their text or number content, and values that have no JSON form (undefined, non-finite floats) are reported as `null`.
4. **One entry per credential or document.** Each credential in a response gets its own `credential_claims` entry. This includes every credential nested inside a W3C presentation and every document in an mdoc device response. Issuer, trust and evidence details are now per child credential.
5. **Incomplete responses are refused.** A credential that does not hold the requested claims is rejected, and so is a response that cannot be read completely. A response that submits more than one presentation for a query without `multiple` is rejected. Nothing is returned as an empty or partial result.

## What did not change

- Claim keys are the same as before.
- Query semantics are the same: credential `id`, `format`, `meta` type matching and `claim_sets` keep their meaning. Requested claims are now checked against each credential. A claim must be present (all of them, or one complete `claim_sets` option), and a value outside a requested `values` list counts as absent.
- The OpenAPI contract stays at version 1. The `claims` schema is now an object with `additionalProperties: {}`, so any JSON value is allowed.

## Stored sessions

Sessions stored before this change are not repaired. Claims that were already converted when they were stored are read back as stored. Text that merely looks like JSON stays text. Only results produced after this change carry the new types.

## Public API

`MatchedCredential.disclosedClaims` stays `Map<String, Any?>`. Nested objects and arrays arrive as `Map` and `List` values. The new public function `claimValueToJson(value: Any?): JsonElement` converts such a map value to JSON for callers that need the typed form.

## Named verifier selection

A create request that carries a `verifier_id` and arrives without a route that names a verifier runs under that verifier, and a route that names a different verifier is refused. This behavior is already in the create command. `CreateAuthRequestVerifierSelectionTest` now pins it through the command registry.

## Local named-verifier proof

`NamedVerifierLocalStackTest` runs a full presentation over HTTP against a verifier process started separately. It is left out of ordinary runs. Select it with `-Poid4vp.localStackTest=true` and set `OID4VP_LOCAL_STACK_CONFIG` to a private JSON file (fields are listed in the test's KDoc). A missing file, missing field or non-local target fails the run.
