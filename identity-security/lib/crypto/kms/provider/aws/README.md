# AWS KMS durable managed-key creation

A caller with an owning transactional operation journal can install the in-process
`ManagedKeyCreationAttempt` capability for one exact provider and backing alias.
The journal must grant physical creation once, durably, and return its current
revision before the provider sends `CreateKey`. Replayed or ambiguous attempts
must return recovery authority, never a second creation grant. Do not derive a
grant from caller-supplied aliases, tags, request JSON, or a cached authorization.

The provider writes both recovery tags in the `CreateKey` request:

- `sphereon:managed-key-operation`: the stable server-selected operation token.
- `sphereon:managed-key-purpose`: `durable-operation-v1`.

Retries discover the exact tagged key through paginated `ListKeys` and
`ListResourceTags`, then validate its `DescribeKey` custody, state, usage and key
spec before reading its public material. This also recovers a key created before
`CreateAlias` completed. A missing alias or an empty eventually consistent scan
cannot authorize recreation after the journal claim. Such attempts raise
`ManagedKeyCreationUncertainException` and remain pending recovery; they must not
be reported as successfully cleaned up. Multiple matching keys, incomplete
pagination, changed authority, and read failures also prevent creation.

The service principal needs its existing key lifecycle and public/signing
permissions plus `kms:ListKeys`, `kms:ListResourceTags`, and `kms:DescribeKey` for
reconciliation. `CreateKey` with tags also requires `kms:TagResource`. Recovery
reads all candidate keys in the configured account and Region; permission errors
are failures rather than evidence of absence. Restrict modification/removal of
the operation tags to trusted administration because they are durable recovery
evidence. The provider does not repair tags using a later `TagResource` call.

AWS documents [CreateKey permissions and eventual consistency](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html),
[ListKeys pagination](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html),
and [ListResourceTags pagination and permissions](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListResourceTags.html).

A distinct in-process `RECOVER_FOR_REVOCATION` intent may confirm an exact tagged
key already in `PendingDeletion` under fresh revocation authority. It never returns
that key as signing material. Retrying revocation of this exact receipt succeeds
without scheduling deletion a second time.

Existing provider calls without this in-process capability retain their normal
behavior. A capability never crosses the remote command wire.
