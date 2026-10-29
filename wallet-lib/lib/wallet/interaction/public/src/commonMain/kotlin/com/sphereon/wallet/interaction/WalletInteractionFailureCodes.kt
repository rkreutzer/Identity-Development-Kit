/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction

/**
 * Stable machine-readable failure codes the interaction engine can emit on
 * [WalletInteractionError.code]. Construction sites must use these constants, not new raw strings.
 *
 * There is no sealed failure type. Tests collect these constants by JVM reflection over this
 * object's public String fields so a new const val without a [DISPOSITIONS] entry fails the build.
 */
object WalletInteractionFailureCodes {
    const val NO_ADAPTER: String = "wallet_interaction.no_adapter"
    const val UNKNOWN_ADAPTER: String = "wallet_interaction.unknown_adapter"
    const val REVISION_CONFLICT: String = WalletInteractionApiConstants.Errors.REVISION_CONFLICT

    const val OID4VCI_OFFER_PARSE_FAILED: String = "oid4vci.offer_parse_failed"
    const val OID4VCI_ISSUER_BLOCKED: String = "oid4vci.issuer_blocked"
    const val OID4VCI_WALLET_INITIATED_INPUT_INVALID: String = "oid4vci.wallet_initiated_input_invalid"
    const val OID4VCI_REFRESH_CREDENTIAL_RECORD_ID_MISSING: String = "oid4vci.refresh_credential_record_id_missing"
    const val OID4VCI_REFRESH_UNEXPECTED_RESULT: String = "oid4vci.refresh_unexpected_result"
    const val OID4VCI_ACTION_CONTINUE_NOT_ALLOWED: String = "oid4vci.action_continue_not_allowed"
    const val OID4VCI_ACTION_SELECTION_NOT_ALLOWED: String = "oid4vci.action_selection_not_allowed"
    const val OID4VCI_ACTION_TX_CODE_NOT_ALLOWED: String = "oid4vci.action_tx_code_not_allowed"
    const val OID4VCI_TX_CODE_REF_INVALID: String = "oid4vci.tx_code_ref_invalid"
    const val OID4VCI_ACTION_AUTH_CALLBACK_NOT_ALLOWED: String = "oid4vci.action_auth_callback_not_allowed"
    const val OID4VCI_AUTH_CALLBACK_REF_INVALID: String = "oid4vci.auth_callback_ref_invalid"
    const val OID4VCI_ACTION_SECURITY_GRANT_NOT_ALLOWED: String = "oid4vci.action_security_grant_not_allowed"
    const val OID4VCI_SECURITY_GRANT_REF_INVALID: String = "oid4vci.security_grant_ref_invalid"
    const val OID4VCI_ACTION_NOT_ALLOWED: String = "oid4vci.action_not_allowed"
    const val OID4VCI_ACTION_COUNTERPARTY_RESOLUTION_NOT_ALLOWED: String = "oid4vci.action_counterparty_resolution_not_allowed"
    const val OID4VCI_COUNTERPARTY_ENCOUNTER_MISSING: String = "oid4vci.counterparty_encounter_missing"
    const val OID4VCI_COUNTERPARTY_ASSOCIATION_MISSING: String = "oid4vci.counterparty_association_missing"
    const val OID4VCI_OFFER_SELECTION_EMPTY: String = "oid4vci.offer_selection_empty"
    const val OID4VCI_OFFER_SELECTION_DUPLICATE: String = "oid4vci.offer_selection_duplicate"
    const val OID4VCI_OFFER_SELECTION_UNKNOWN: String = "oid4vci.offer_selection_unknown"
    const val OID4VCI_SECURITY_DENIED: String = "oid4vci.security_denied"
    const val OID4VCI_EXECUTION_NOT_CONFIGURED: String = "oid4vci.execution_not_configured"
    const val OID4VCI_CREDENTIAL_OFFER_MISSING: String = "oid4vci.credential_offer_missing"
    const val OID4VCI_OFFER_RESOLVE_FAILED: String = "oid4vci.offer_resolve_failed"
    const val OID4VCI_OPTIONS_UNAVAILABLE: String = "oid4vci.options_unavailable"
    const val OID4VCI_AUTHORIZATION_SERVER_RESOLVE_FAILED: String = "oid4vci.authorization_server_resolve_failed"
    const val OID4VCI_ATTESTATION_CHALLENGE_FAILED: String = "oid4vci.attestation_challenge_failed"
    const val OID4VCI_TOKEN_PROOFS_FAILED: String = "oid4vci.token_proofs_failed"
    const val OID4VCI_TOKEN_EXCHANGE_FAILED: String = "oid4vci.token_exchange_failed"
    const val OID4VCI_NONCE_REQUEST_FAILED: String = "oid4vci.nonce_request_failed"
    const val OID4VCI_CREDENTIAL_DPOP_PROOF_FAILED: String = "oid4vci.credential_dpop_proof_failed"
    const val OID4VCI_CREDENTIAL_REQUEST_FAILED: String = "oid4vci.credential_request_failed"
    const val OID4VCI_REFRESH_RECORD_LOOKUP_FAILED: String = "oid4vci.refresh_record_lookup_failed"
    const val OID4VCI_REFRESH_RECORD_NOT_FOUND: String = "oid4vci.refresh_record_not_found"
    const val OID4VCI_REFRESH_STATE_MISSING: String = "oid4vci.refresh_state_missing"
    const val OID4VCI_REFRESH_METHOD_UNSUPPORTED: String = "oid4vci.refresh_method_unsupported"
    const val OID4VCI_REFRESH_PROVENANCE_MISSING: String = "oid4vci.refresh_provenance_missing"
    const val OID4VCI_REFRESH_MULTIPLE_ACTIVE_INSTANCES_UNSUPPORTED: String = "oid4vci.refresh_multiple_active_instances_unsupported"
    const val OID4VCI_REFRESH_HOLDER_KEY_MISSING: String = "oid4vci.refresh_holder_key_missing"
    const val OID4VCI_REFRESH_TOKEN_LOOKUP_FAILED: String = "oid4vci.refresh_token_lookup_failed"
    const val OID4VCI_REFRESH_TOKEN_MISSING: String = "oid4vci.refresh_token_missing"
    const val OID4VCI_REFRESH_ISSUER_METADATA_FAILED: String = "oid4vci.refresh_issuer_metadata_failed"
    const val OID4VCI_REFRESH_CREDENTIAL_CONFIGURATION_UNKNOWN: String = "oid4vci.refresh_credential_configuration_unknown"
    const val OID4VCI_REFRESH_CREDENTIAL_FORMAT_UNSUPPORTED: String = "oid4vci.refresh_credential_format_unsupported"
    const val OID4VCI_REFRESH_AUTHORIZATION_SERVER_RESOLVE_FAILED: String = "oid4vci.refresh_authorization_server_resolve_failed"
    const val OID4VCI_REFRESH_OPTIONS_UNAVAILABLE: String = "oid4vci.refresh_options_unavailable"
    const val OID4VCI_REFRESH_TOKEN_EXCHANGE_FAILED: String = "oid4vci.refresh_token_exchange_failed"
    const val OID4VCI_REFRESH_NONCE_REQUEST_FAILED: String = "oid4vci.refresh_nonce_request_failed"
    const val OID4VCI_REFRESH_KEY_ATTESTATION_FAILED: String = "oid4vci.refresh_key_attestation_failed"
    const val OID4VCI_REFRESH_PROOF_CREATION_FAILED: String = "oid4vci.refresh_proof_creation_failed"
    const val OID4VCI_REFRESH_CREDENTIAL_DPOP_PROOF_FAILED: String = "oid4vci.refresh_credential_dpop_proof_failed"
    const val OID4VCI_REFRESH_CREDENTIAL_REQUEST_FAILED: String = "oid4vci.refresh_credential_request_failed"
    const val OID4VCI_REFRESH_DEFERRED_UNSUPPORTED: String = "oid4vci.refresh_deferred_unsupported"
    const val OID4VCI_DEFERRED_ENDPOINT_MISSING: String = "oid4vci.deferred_endpoint_missing"
    const val OID4VCI_ACCESS_TOKEN_MISSING: String = "oid4vci.access_token_missing"
    const val OID4VCI_DEFERRED_DPOP_PROOF_FAILED: String = "oid4vci.deferred_dpop_proof_failed"
    const val OID4VCI_DEFERRED_REQUEST_FAILED: String = "oid4vci.deferred_request_failed"
    /** The authorization for a deferred credential lapsed and cannot be refreshed; the offer has to be restarted. */
    const val OID4VCI_OFFER_EXPIRED: String = "oid4vci.offer_expired"
    const val OID4VCI_UNSUPPORTED_GRANT: String = "oid4vci.unsupported_grant"
    const val OID4VCI_CLIENT_ID_MISSING: String = "oid4vci.client_id_missing"
    const val OID4VCI_REDIRECT_URI_MISSING: String = "oid4vci.redirect_uri_missing"
    const val OID4VCI_AUTHORIZATION_ENDPOINT_MISSING: String = "oid4vci.authorization_endpoint_missing"
    const val OID4VCI_PAR_ENDPOINT_MISSING: String = "oid4vci.par_endpoint_missing"
    const val OID4VCI_AUTHORIZATION_REQUEST_FAILED: String = "oid4vci.authorization_request_failed"
    const val OID4VCI_IAE_INITIATE_FAILED: String = "oid4vci.iae_initiate_failed"
    const val OID4VCI_IAE_ENDPOINT_MISSING: String = "oid4vci.iae_endpoint_missing"
    const val OID4VCI_IAE_AUTH_SESSION_MISSING: String = "oid4vci.iae_auth_session_missing"
    const val OID4VCI_IAE_FOLLOW_UP_FAILED: String = "oid4vci.iae_follow_up_failed"
    const val OID4VCI_IAE_ERROR: String = "oid4vci.iae_error"
    const val OID4VCI_IAE_INTERACTION_UNSUPPORTED: String = "oid4vci.iae_interaction_unsupported"
    const val OID4VCI_IAE_OPENID4VP_REQUEST_MISSING: String = "oid4vci.iae_openid4vp_request_missing"
    const val OID4VCI_TOKEN_ENDPOINT_MISSING: String = "oid4vci.token_endpoint_missing"
    const val OID4VCI_IAE_CODE_VERIFIER_MISSING: String = "oid4vci.iae_code_verifier_missing"
    const val OID4VCI_AUTHORIZATION_CODE_EXCHANGE_FAILED: String = "oid4vci.authorization_code_exchange_failed"
    const val OID4VCI_KEY_ATTESTATION_FAILED: String = "oid4vci.key_attestation_failed"
    const val OID4VCI_PROOF_CREATION_FAILED: String = "oid4vci.proof_creation_failed"
    const val OID4VCI_HOLDER_KEY_PROVISIONING_FAILED: String = "oid4vci.holder_key_provisioning_failed"
    const val OID4VCI_EMPTY_CREDENTIAL_RESPONSE: String = "oid4vci.empty_credential_response"
    const val OID4VCI_CREDENTIAL_RECEIVER_FAILED: String = "oid4vci.credential_receiver_failed"
    const val OID4VCI_NOTIFICATION_FAILED: String = "oid4vci.notification_failed"
    const val OID4VCI_CODE_VERIFIER_MISSING: String = "oid4vci.code_verifier_missing"
    const val OID4VCI_AUTHORIZATION_RESPONSE_INVALID: String = "oid4vci.authorization_response_invalid"
    /** The authorization redirect belongs to another request; the receive keeps waiting for its own. */
    const val OID4VCI_AUTHORIZATION_STATE_MISMATCH: String = "oid4vci.authorization_state_mismatch"

    const val OID4VP_REQUEST_RESOLVE_FAILED: String = "oid4vp.request_resolve_failed"
    const val OID4VP_VERIFIER_BLOCKED: String = "oid4vp.verifier_blocked"
    const val OID4VP_COUNTERPARTY_RESOLUTION_REQUIRED: String = "oid4vp.counterparty_resolution_required"
    const val OID4VP_SECURITY_GRANT_REF_INVALID: String = "oid4vp.security_grant_ref_invalid"
    const val OID4VP_ACTION_COUNTERPARTY_RESOLUTION_NOT_ALLOWED: String = "oid4vp.action_counterparty_resolution_not_allowed"
    const val OID4VP_COUNTERPARTY_ENCOUNTER_MISSING: String = "oid4vp.counterparty_encounter_missing"
    const val OID4VP_COUNTERPARTY_ASSOCIATION_MISSING: String = "oid4vp.counterparty_association_missing"
    const val OID4VP_SECURITY_DENIED: String = "oid4vp.security_denied"
    const val OID4VP_DIGITAL_CREDENTIAL_PROTOCOL_MISSING: String = "oid4vp.digital_credential_protocol_missing"
    const val OID4VP_DCA_SELECTION_INVALID: String = "oid4vp.digital_credentials_selection_invalid"
    const val OID4VP_DCA_SELECTION_UNAVAILABLE: String = "oid4vp.digital_credentials_selection_unavailable"
    const val OID4VP_DCA_SELECTION_MISMATCH: String = "oid4vp.digital_credentials_selection_mismatch"
    const val OID4VP_SELECTION_UNSATISFIABLE: String = "oid4vp.selection_unsatisfiable"
    const val OID4VP_SELECTION_UNKNOWN_REQUIREMENT: String = "oid4vp.selection_unknown_requirement"
    const val OID4VP_SELECTION_MISSING_REQUIREMENT: String = "oid4vp.selection_missing_requirement"
    const val OID4VP_SELECTION_MULTIPLE_NOT_ALLOWED: String = "oid4vp.selection_multiple_not_allowed"
    const val OID4VP_SELECTION_CREDENTIAL_NOT_CANDIDATE: String = "oid4vp.selection_credential_not_candidate"
    const val OID4VP_REQUEST_URI_EXPIRED: String = "oid4vp.request_uri_expired"
    const val OID4VP_REQUEST_URI_NOT_FOUND: String = "oid4vp.request_uri_not_found"
    const val OID4VP_REQUEST_URI_FETCH_FAILED: String = "oid4vp.request_uri_fetch_failed"
    const val OID4VP_REQUEST_URI_REJECTED: String = "oid4vp.request_uri_rejected"
    const val OID4VP_REQUEST_PARSE_FAILED: String = "oid4vp.request_parse_failed"
    const val OID4VP_EXECUTION_NOT_CONFIGURED: String = "oid4vp.execution_not_configured"
    const val OID4VP_AUTHORIZATION_REQUEST_MISSING: String = "oid4vp.authorization_request_missing"
    const val OID4VP_CREDENTIAL_RESOLUTION_FAILED: String = "oid4vp.credential_resolution_failed"
    const val OID4VP_RESPONSE_CREATION_FAILED: String = "oid4vp.response_creation_failed"
    const val OID4VP_RESPONSE_SUBMISSION_FAILED: String = "oid4vp.response_submission_failed"
    const val OID4VP_PRESENTATION_HISTORY_UPDATE_FAILED: String = "oid4vp.presentation_history_update_failed"
    const val OID4VP_VERIFIER_ERROR: String = "oid4vp.verifier_error"
    const val OID4VP_NESTED_REQUEST_MISSING: String = "oid4vp.nested_request_missing"
    const val OID4VP_NESTED_REQUEST_PARSE_FAILED: String = "oid4vp.nested_request_parse_failed"

    const val NESTED_PRESENTATION_NOT_CONFIGURED: String = "wallet_nested_presentation.not_configured"

    const val ISO18013_TRANSPORT_UNAVAILABLE: String = "iso18013.transport_unavailable"
    const val ISO18013_ENGAGEMENT_FAILED: String = "iso18013.engagement_failed"
    const val ISO18013_READER_BLOCKED: String = "iso18013.reader_blocked"
    const val ISO18013_SECURITY_GRANT_REF_INVALID: String = "iso18013.security_grant_ref_invalid"
    const val ISO18013_ACTION_COUNTERPARTY_RESOLUTION_NOT_ALLOWED: String = "iso18013.action_counterparty_resolution_not_allowed"
    const val ISO18013_SECURITY_DENIED: String = "iso18013.security_denied"
    const val ISO18013_EXECUTION_NOT_CONFIGURED: String = "iso18013.execution_not_configured"
    const val ISO18013_ENGAGEMENT_MISSING: String = "iso18013.engagement_missing"
    const val ISO18013_DEVICE_RESPONSE_FAILED: String = "iso18013.device_response_failed"
}

/**
 * Deliberate disposition for every emitted code. Construction sites must pass disposition through
 * [classifiedWalletInteractionError] rather than inventing a value or relying on the decode default.
 */
val DISPOSITIONS: Map<String, WalletFailureDisposition> =
    mapOf(
        WalletInteractionFailureCodes.NO_ADAPTER to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.UNKNOWN_ADAPTER to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.REVISION_CONFLICT to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_OFFER_PARSE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_ISSUER_BLOCKED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_WALLET_INITIATED_INPUT_INVALID to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_RECORD_ID_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_UNEXPECTED_RESULT to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_ACTION_CONTINUE_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_ACTION_SELECTION_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_ACTION_TX_CODE_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_TX_CODE_REF_INVALID to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_ACTION_AUTH_CALLBACK_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_AUTH_CALLBACK_REF_INVALID to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_ACTION_SECURITY_GRANT_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_SECURITY_GRANT_REF_INVALID to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_ACTION_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_ACTION_COUNTERPARTY_RESOLUTION_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_COUNTERPARTY_ENCOUNTER_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_COUNTERPARTY_ASSOCIATION_MISSING to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_OFFER_SELECTION_EMPTY to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_OFFER_SELECTION_DUPLICATE to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_OFFER_SELECTION_UNKNOWN to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_SECURITY_DENIED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_EXECUTION_NOT_CONFIGURED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_OFFER_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_OFFER_RESOLVE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_OPTIONS_UNAVAILABLE to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_SERVER_RESOLVE_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_ATTESTATION_CHALLENGE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_TOKEN_PROOFS_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_TOKEN_EXCHANGE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_NONCE_REQUEST_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_DPOP_PROOF_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_REQUEST_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_RECORD_LOOKUP_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_RECORD_NOT_FOUND to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_STATE_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_METHOD_UNSUPPORTED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_PROVENANCE_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_MULTIPLE_ACTIVE_INSTANCES_UNSUPPORTED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_HOLDER_KEY_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_TOKEN_LOOKUP_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_TOKEN_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_ISSUER_METADATA_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_CONFIGURATION_UNKNOWN to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_FORMAT_UNSUPPORTED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_AUTHORIZATION_SERVER_RESOLVE_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_OPTIONS_UNAVAILABLE to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_TOKEN_EXCHANGE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_NONCE_REQUEST_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_KEY_ATTESTATION_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_PROOF_CREATION_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_DPOP_PROOF_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_REQUEST_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REFRESH_DEFERRED_UNSUPPORTED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_DEFERRED_ENDPOINT_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_ACCESS_TOKEN_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_DEFERRED_DPOP_PROOF_FAILED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VCI_OFFER_EXPIRED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_UNSUPPORTED_GRANT to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_CLIENT_ID_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_REDIRECT_URI_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_ENDPOINT_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_PAR_ENDPOINT_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_REQUEST_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_IAE_INITIATE_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_IAE_ENDPOINT_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_IAE_AUTH_SESSION_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_IAE_FOLLOW_UP_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_IAE_ERROR to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_IAE_INTERACTION_UNSUPPORTED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_IAE_OPENID4VP_REQUEST_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_TOKEN_ENDPOINT_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_IAE_CODE_VERIFIER_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_CODE_EXCHANGE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_KEY_ATTESTATION_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_PROOF_CREATION_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_HOLDER_KEY_PROVISIONING_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VCI_EMPTY_CREDENTIAL_RESPONSE to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_RECEIVER_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_NOTIFICATION_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_CODE_VERIFIER_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_RESPONSE_INVALID to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_STATE_MISMATCH to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VP_REQUEST_RESOLVE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_VERIFIER_BLOCKED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_COUNTERPARTY_RESOLUTION_REQUIRED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_SECURITY_GRANT_REF_INVALID to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_ACTION_COUNTERPARTY_RESOLUTION_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_COUNTERPARTY_ENCOUNTER_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_COUNTERPARTY_ASSOCIATION_MISSING to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_SECURITY_DENIED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_DIGITAL_CREDENTIAL_PROTOCOL_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_DCA_SELECTION_INVALID to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_DCA_SELECTION_UNAVAILABLE to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_DCA_SELECTION_MISMATCH to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_SELECTION_UNSATISFIABLE to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_SELECTION_UNKNOWN_REQUIREMENT to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_SELECTION_MISSING_REQUIREMENT to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_SELECTION_MULTIPLE_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_SELECTION_CREDENTIAL_NOT_CANDIDATE to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_REQUEST_URI_EXPIRED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_REQUEST_URI_NOT_FOUND to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_REQUEST_URI_FETCH_FAILED to WalletFailureDisposition.REPEATABLE,
        WalletInteractionFailureCodes.OID4VP_REQUEST_URI_REJECTED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_EXECUTION_NOT_CONFIGURED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_AUTHORIZATION_REQUEST_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_CREDENTIAL_RESOLUTION_FAILED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_RESPONSE_SUBMISSION_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_PRESENTATION_HISTORY_UPDATE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_VERIFIER_ERROR to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_NESTED_REQUEST_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.OID4VP_NESTED_REQUEST_PARSE_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.NESTED_PRESENTATION_NOT_CONFIGURED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.ISO18013_TRANSPORT_UNAVAILABLE to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.ISO18013_ENGAGEMENT_FAILED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.ISO18013_READER_BLOCKED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.ISO18013_SECURITY_GRANT_REF_INVALID to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.ISO18013_ACTION_COUNTERPARTY_RESOLUTION_NOT_ALLOWED to WalletFailureDisposition.RESUMABLE,
        WalletInteractionFailureCodes.ISO18013_SECURITY_DENIED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.ISO18013_EXECUTION_NOT_CONFIGURED to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.ISO18013_ENGAGEMENT_MISSING to WalletFailureDisposition.TERMINAL,
        WalletInteractionFailureCodes.ISO18013_DEVICE_RESPONSE_FAILED to WalletFailureDisposition.TERMINAL,
    )

val SINGLE_USE_SPENT_CODES: Set<String> =
    setOf(
        WalletInteractionFailureCodes.OID4VCI_TOKEN_EXCHANGE_FAILED,
        WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_CODE_EXCHANGE_FAILED,
        WalletInteractionFailureCodes.OID4VCI_IAE_ERROR,
        WalletInteractionFailureCodes.OID4VP_REQUEST_URI_EXPIRED,
        WalletInteractionFailureCodes.OID4VP_REQUEST_URI_NOT_FOUND,
    )

/**
 * Projects a classified [WalletInteractionError]. Looks the disposition up in [DISPOSITIONS] so a
 * newly emitted code without a table entry fails here instead of defaulting to TERMINAL on decode.
 *
 * Does not populate [WalletInteractionError.message]. Consumers resolve holder-facing copy locally
 * from [WalletInteractionFailureCatalogue] via [resolveFailureMessage]; `message` stays the first
 * rung of that ladder if the engine itself ever resolves prose.
 */
fun classifiedWalletInteractionError(
    code: String,
    messageKey: String? = null,
    arguments: Map<String, String> = emptyMap(),
): WalletInteractionError =
    WalletInteractionError(
        code = code,
        disposition = DISPOSITIONS.getValue(code),
        messageKey = messageKey,
        arguments = arguments,
    )

/**
 * Disposition for an open-ended mapped error code. Unknown codes are TERMINAL.
 */
fun dispositionFor(code: String): WalletFailureDisposition =
    DISPOSITIONS[code] ?: WalletFailureDisposition.TERMINAL
