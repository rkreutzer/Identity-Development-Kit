/*
 * Copyright (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

@file:Suppress("UNCHECKED_CAST")

package com.sphereon.crypto.kms.rest.server.service

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.NotFoundException
import com.sphereon.core.compat.LocalDateTimeKMP
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.ResolvedKeyInfoType
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.generic.CertificateSigningRequest
import com.sphereon.crypto.core.generic.X509DistinguishedNameElements
import com.sphereon.crypto.core.kms.CertificateService
import com.sphereon.crypto.core.kms.CertificateStoreService
import com.sphereon.crypto.core.kms.HasKeyStoreService
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.generateJwkThumbprint
import com.sphereon.crypto.certificate.persistence.CertificateReferenceKind
import com.sphereon.crypto.certificate.persistence.CertificateReferenceRecord
import com.sphereon.crypto.certificate.persistence.CertificateReferenceSource
import com.sphereon.crypto.certificate.persistence.CertificateReferenceStoreErrorCodes
import com.sphereon.crypto.core.ResourceControlMode
import com.sphereon.core.api.model.Origin
import com.sphereon.crypto.kms.rest.api.command.CertificateReferenceResponse
import com.sphereon.crypto.kms.rest.api.command.CertificateReferenceMetadataResponse
import com.sphereon.crypto.kms.rest.api.command.CertificateReferencesResponse
import com.sphereon.crypto.kms.rest.api.command.RegisterCertificateReferenceInput
import com.sphereon.crypto.core.x509.Certificate
import com.sphereon.crypto.core.x509.certificateChainFromDer
import com.sphereon.crypto.core.x509.certificateFromDer
import com.sphereon.crypto.kms.rest.api.generated.infrastructure.Base64ByteArray
import com.sphereon.crypto.kms.rest.api.generated.models.CertificateAliasesResponse
import com.sphereon.crypto.kms.rest.api.generated.models.CertificateBytesResponse
import com.sphereon.crypto.kms.rest.api.generated.models.CertificateChainResponse
import com.sphereon.crypto.kms.rest.api.generated.models.CertificateResponse
import com.sphereon.crypto.kms.rest.api.generated.models.CertificateSigningRequestResponse
import com.sphereon.crypto.kms.rest.api.generated.models.GenerateCertificateSigningRequestRequest
import com.sphereon.crypto.kms.rest.api.generated.models.IssueCertificateFromCsrRequest
import com.sphereon.crypto.kms.rest.api.generated.models.IssueCertificateRequest
import com.sphereon.crypto.kms.rest.api.generated.models.StoreCertificateChainRequest
import com.sphereon.crypto.kms.rest.api.generated.models.StoreCertificateRequest
import com.sphereon.crypto.kms.rest.api.generated.models.X509DistinguishedName
import com.sphereon.crypto.kms.rest.api.mapper.toRest
import com.sphereon.crypto.kms.rest.api.mapper.toSdk
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atTime
import kotlinx.datetime.plus
import kotlinx.datetime.toLocalDateTime
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.time.Clock

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<CertificatesRestService>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("CertificatesRestServiceImpl", exact = true)
class CertificatesRestServiceImpl(
    private val kms: KeyManagerService,
    private val certificateService: CertificateService,
    private val certificateReferenceRegistrar: CertificateReferenceRegistrar,
    private val platformManagedCertificateAliasLister: PlatformManagedCertificateAliasLister,
) : CertificatesRestService {
    override suspend fun registerCertificateReference(request: RegisterCertificateReferenceInput): CertificateReferenceResponse =
        certificateReferenceRegistrar.register(request).getOrElse { error ->
            throw CertificateReferenceResolutionException(code = error.code, message = registrationErrorMessage(error))
        }.toResponse()

    override suspend fun listCertificateReferences(
        providerId: String?,
        kind: CertificateReferenceKind?,
        source: CertificateReferenceSource?,
    ): CertificateReferencesResponse =
        CertificateReferencesResponse(
            references = certificateReferenceRegistrar
                .list(providerId, kind, source)
                .getOrThrowReference()
                .map { it.toMetadataResponse() },
        )

    override suspend fun getCertificateReference(id: String): CertificateReferenceMetadataResponse {
        val record = certificateReferenceRegistrar.findById(id).getOrThrowReference()
            ?: throw CertificateReferenceResolutionException("NOT_FOUND_ERROR", "The certificate reference was not found")
        return record.toMetadataResponse()
    }

    override suspend fun generateCsr(request: GenerateCertificateSigningRequestRequest): CertificateSigningRequestResponse {
        val csr =
            certificateService.generateCSR(
                subjectKeyInfo = request.subjectKeyInfo.toSdk(),
                distinguishedNameElements = request.subject.toSdk(),
                serialNumber = request.serialNumber ?: 1,
            )
        return csr.toRestResponse()
    }

    override suspend fun issueCertificate(request: IssueCertificateRequest): CertificateResponse {
        val issuerKeyInfo = request.issuerKeyInfo.toSdk() as KeyInfoType<KeyType>
        val subjectKeyInfo = request.subjectKeyInfo.toSdk() as ResolvedKeyInfoType<KeyType>
        val extensions =
            CertificateIssuanceExtensions.create(
                certificateAuthorityPathLengthConstraint = request.certificateAuthorityPathLengthConstraint,
                keyUsage = request.keyUsage?.map { it.value },
            )
        if (request.certificateAuthorityPathLengthConstraint != null) {
            require(request.issuer.toSdk() == request.subject.toSdk()) {
                "A self-signed certificate authority must use the same issuer and subject name"
            }
            require(
                issuerKeyInfo.providerId == subjectKeyInfo.providerId && issuerKeyInfo.alias == subjectKeyInfo.alias,
            ) {
                "A self-signed certificate authority must use the same managed issuer and subject key"
            }
            requireManagedSubjectKey(subjectKeyInfo)
        } else if (request.keyUsage?.isNotEmpty() == true) {
            requireManagedSubjectKey(subjectKeyInfo)
        }
        val result =
            certificateService.createCertificate(
                issuerKeyInfo = issuerKeyInfo,
                issuer = request.issuer.toSdk(),
                subjectKeyInfo = subjectKeyInfo,
                subject = request.subject.toSdk(),
                serialNumber = request.serialNumber,
                extensions = extensions,
                notBefore = request.notBefore?.let { LocalDateTimeKMP.fromString(it) } ?: LocalDateTimeKMP.now(),
                notAfter = request.notAfter?.let { LocalDateTimeKMP.fromString(it) } ?: defaultNotAfter(),
            )
        return CertificateResponse(
            certificate = Base64ByteArray(result.certificate.der),
            keyInfo = result.keyInfo.toRest(),
        )
    }

    private suspend fun requireManagedSubjectKey(subjectKeyInfo: ResolvedKeyInfoType<KeyType>) {
        val providerId = requireNotNull(subjectKeyInfo.providerId) {
            "Certificate extensions require a managed subject key with a provider id"
        }
        val alias = requireNotNull(subjectKeyInfo.alias) {
            "Certificate extensions require a managed subject key with an alias"
        }
        val managed = kms.getProviderById(providerId).getKey(KeyInfo<Jwk>(providerId = providerId, alias = alias))
        require(managed.providerId == providerId && managed.alias == alias) {
            "Certificate subject does not resolve to the requested managed key"
        }
        val requestedThumbprint =
            generateJwkThumbprint(CoseJoseKeyMappingService.toJoseJwk(subjectKeyInfo.key).toPublicKey())
        val managedThumbprint = generateJwkThumbprint(CoseJoseKeyMappingService.toJoseJwk(managed.key).toPublicKey())
        require(requestedThumbprint == managedThumbprint) {
            "Certificate subject public key does not match the requested managed key"
        }
    }

    override suspend fun issueCertificateFromCsr(request: IssueCertificateFromCsrRequest): CertificateResponse {
        val csr = request.csr.toSdk()
        val result =
            certificateService.createCertificateFromCSR(
                issuerKeyInfo = request.issuerKeyInfo.toSdk() as KeyInfoType<KeyType>,
                issuer = request.issuer.toSdk(),
                subjectKeyInfo = request.subjectKeyInfo.toSdk() as ResolvedKeyInfoType<KeyType>,
                csr = csr,
                serialNumber = request.serialNumber ?: csr.serialNumber,
                notBefore = request.notBefore?.let { LocalDateTimeKMP.fromString(it) } ?: LocalDateTimeKMP.now(),
                notAfter = request.notAfter?.let { LocalDateTimeKMP.fromString(it) } ?: defaultNotAfter(),
            )
        return CertificateResponse(
            certificate = Base64ByteArray(result.certificate.der),
            keyInfo = result.keyInfo.toRest(),
        )
    }

    override suspend fun listTrustedCertificateAliases(providerId: String?): CertificateAliasesResponse {
        val referenceAliases = certificateReferenceRegistrar
            .list(providerId, CertificateReferenceKind.TRUSTED_CERTIFICATE)
            .getOrThrowReference()
            .map { it.alias }
        val platformAliases = platformManagedCertificateAliasLister.listTrustedCertificateAliases(providerId)
        return CertificateAliasesResponse(aliases = (referenceAliases + platformAliases).distinct().toTypedArray())
    }

    override suspend fun getTrustedCertificate(
        alias: String,
        providerId: String?
    ): CertificateBytesResponse {
        val record = certificateReferenceRegistrar
            .findLatest(alias, providerId, CertificateReferenceKind.TRUSTED_CERTIFICATE)
            .getOrThrowReference()
        if (record == null) {
            return CertificateBytesResponse(certificate = Base64ByteArray(certificateStore(providerId).getCertificate(alias).der))
        }
        if (record.deletedAt != null) throw CertificateReferenceResolutionException("NOT_FOUND_ERROR", "The certificate reference is deleted")
        val der = when (record.source) {
            CertificateReferenceSource.STORED_PUBLIC_MATERIAL -> {
                val stored = certificateReferenceRegistrar.storedChain(record).getOrThrowReference()
                certificateReferenceRegistrar.verifyStoredRead(record, stored).getOrThrowReference()
                stored.first()
            }
            CertificateReferenceSource.PROVIDER_NATIVE -> {
                val fresh = certificateReferenceRegistrar.inspectProvider(record).getOrThrowReference()
                certificateReferenceRegistrar.verifyProviderRead(record, fresh).getOrThrowReference()
                fresh.certificate.der
            }
        }
        return CertificateBytesResponse(certificate = Base64ByteArray(der))
    }

    override suspend fun storeTrustedCertificate(
        alias: String,
        request: StoreCertificateRequest,
        providerId: String?,
    ): CertificateBytesResponse {
        val cert = certificateFromDer(request.certificate.value)
        val effectiveProviderId = providerId ?: kms.defaultProviderId()
        val store = certificateStore(providerId)
        ensureTrustedCertificateAliasAbsent(store, alias)
        val reservation = certificateReferenceRegistrar.reservePlatformManaged(
            RegisterCertificateReferenceInput(
                providerId = effectiveProviderId,
                alias = alias,
                kind = CertificateReferenceKind.TRUSTED_CERTIFICATE,
                source = CertificateReferenceSource.STORED_PUBLIC_MATERIAL,
                certificateChain = listOf(Base64ByteArray(cert.der)),
            ),
        ).getOrThrowReference()
        storeWithReservation(reservation) {
            store.storeTrustedCertificate(alias, cert)
        }
        return CertificateBytesResponse(certificate = Base64ByteArray(cert.der))
    }

    override suspend fun deleteTrustedCertificate(
        alias: String,
        providerId: String?
    ): Boolean {
        val record = certificateReferenceRegistrar
            .findLatest(alias, providerId, CertificateReferenceKind.TRUSTED_CERTIFICATE)
            .getOrThrowReference()
        if (record == null) return false
        if (record.deletedAt != null) return record.controlMode == ResourceControlMode.EXTERNALLY_MANAGED
        if (record.controlMode == ResourceControlMode.EXTERNALLY_MANAGED) {
            return certificateReferenceRegistrar.softDelete(record).getOrThrowReference()
        }
        val deleted = certificateStore(record.providerId).deleteCertificate(alias)
        if (deleted) certificateReferenceRegistrar.softDelete(record).getOrThrowReference()
        return deleted
    }

    override suspend fun listCertificateChainAliases(providerId: String?): CertificateAliasesResponse {
        val referenceAliases = certificateReferenceRegistrar
            .list(providerId, CertificateReferenceKind.KEY_CERTIFICATE_CHAIN)
            .getOrThrowReference()
            .map { it.alias }
        val platformAliases = platformManagedCertificateAliasLister.listCertificateChainAliases(providerId)
        return CertificateAliasesResponse(aliases = (referenceAliases + platformAliases).distinct().toTypedArray())
    }

    override suspend fun getCertificateChain(
        alias: String,
        providerId: String?
    ): CertificateChainResponse {
        val record = certificateReferenceRegistrar
            .findLatest(alias, providerId, CertificateReferenceKind.KEY_CERTIFICATE_CHAIN)
            .getOrThrowReference()
        if (record == null) {
            return CertificateChainResponse(
                certificates = certificateStore(providerId).getCertificateChain(alias).map { Base64ByteArray(it.der) }.toTypedArray(),
            )
        }
        if (record.deletedAt != null) throw CertificateReferenceResolutionException("NOT_FOUND_ERROR", "The certificate chain reference is deleted")
        val der = when (record.source) {
            CertificateReferenceSource.STORED_PUBLIC_MATERIAL -> {
                val stored = certificateReferenceRegistrar.storedChain(record).getOrThrowReference()
                certificateReferenceRegistrar.verifyStoredRead(record, stored).getOrThrowReference()
                stored
            }
            CertificateReferenceSource.PROVIDER_NATIVE -> {
                val fresh = certificateReferenceRegistrar.inspectProvider(record).getOrThrowReference()
                certificateReferenceRegistrar.verifyProviderRead(record, fresh).getOrThrowReference()
                certificateReferenceRegistrar
                    .completeChainFromTrustStore(fresh.certificate.der, record.providerId)
                    .getOrThrowReference()
            }
        }
        return CertificateChainResponse(certificates = der.map { Base64ByteArray(it) }.toTypedArray())
    }

    override suspend fun storeCertificateChain(
        alias: String,
        request: StoreCertificateChainRequest,
        providerId: String?,
    ): CertificateChainResponse {
        val chain = submittedKeyCertificateChain(request)
        val effectiveProviderId = providerId ?: kms.defaultProviderId()
        val store = certificateStore(providerId)
        val providerChain = existingProviderObject { store.getCertificateChain(alias).takeIf { it.isNotEmpty() } }
        val keyInfo = request.keyInfo?.toSdk()
        val input = RegisterCertificateReferenceInput(
            providerId = effectiveProviderId,
            alias = alias,
            kind = CertificateReferenceKind.KEY_CERTIFICATE_CHAIN,
            source = CertificateReferenceSource.STORED_PUBLIC_MATERIAL,
            linkedKeyAlias = keyInfo?.alias ?: alias,
            certificateChain = chain.map { Base64ByteArray(it.der) },
        )
        val reserved =
            if (providerChain == null) {
                certificateReferenceRegistrar.reservePlatformManaged(input)
            } else {
                certificateReferenceRegistrar.reservePlatformManagedChainReplacement(input, providerChain.first().der)
            }
        val reservation = reserved.getOrElse { error ->
            throw CertificateReferenceResolutionException(code = error.code, message = registrationErrorMessage(error))
        }
        storeWithReservation(reservation) {
            store.storeCertificateChain(alias, chain.toTypedArray(), keyInfo)
        }
        return CertificateChainResponse(certificates = chain.map { Base64ByteArray(it.der) }.toTypedArray())
    }

    override suspend fun deleteCertificateChain(
        alias: String,
        providerId: String?
    ): Boolean {
        val record = certificateReferenceRegistrar
            .findLatest(alias, providerId, CertificateReferenceKind.KEY_CERTIFICATE_CHAIN)
            .getOrThrowReference()
        if (record == null) return false
        if (record.deletedAt != null) return record.controlMode == ResourceControlMode.EXTERNALLY_MANAGED
        if (record.controlMode == ResourceControlMode.EXTERNALLY_MANAGED) {
            return certificateReferenceRegistrar.softDelete(record).getOrThrowReference()
        }
        val deleted = certificateStore(record.providerId).deleteCertificateChain(alias)
        if (deleted) certificateReferenceRegistrar.softDelete(record).getOrThrowReference()
        return deleted
    }

    private suspend fun certificateStore(providerId: String?): CertificateStoreService {
        val target: Any =
            if (providerId == null) {
                kms.keyStore
            } else {
                try {
                    kms.getProviderById(providerId)
                } catch (unknownProvider: com.sphereon.crypto.core.PKIException) {
                    // The registry refuses an id it does not hold; that is a caller addressing
                    // error, not a server fault, so it must not surface as a 500.
                    throw CertificateReferenceResolutionException(
                        "KMS_PROVIDER_NOT_FOUND",
                        unknownProvider.message ?: "KMS provider '$providerId' is not configured",
                    )
                }
            }
        return target as? CertificateStoreService
            ?: (target as? HasKeyStoreService)?.keyStore as? CertificateStoreService
            ?: throw IllegalArgumentException(
                "Unsupported operation: ${providerId?.let { "provider '$it'" } ?: "default key store"} does not support certificate store operations.",
            )
    }

    private suspend fun ensureTrustedCertificateAliasAbsent(
        store: CertificateStoreService,
        alias: String,
    ) {
        if (existingProviderObject { store.getCertificate(alias) } != null) {
            throw CertificateReferenceResolutionException(
                "KMS_CERTIFICATE_REFERENCE_MANAGED_STORE_CONFLICT",
                "The certificate alias already exists at the provider",
            )
        }
    }

    /** Only the provider's explicit not-found result proves the alias is unused. */
    private suspend fun <T : Any> existingProviderObject(read: suspend () -> T?): T? =
        try {
            read()
        } catch (_: NotFoundException) {
            null
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            throw CertificateReferenceResolutionException(
                "KMS_CERTIFICATE_PROVIDER_PREFLIGHT_FAILED",
                "The provider certificate alias could not be safely checked",
            )
        }

    private fun submittedKeyCertificateChain(request: StoreCertificateChainRequest): List<Certificate> {
        val chain = try {
            certificateChainFromDer(request.certificates.map { it.value }.toTypedArray()).toList()
        } catch (_: Exception) {
            throw invalidCertificateChain("certificates must contain valid DER certificates")
        }
        if (chain.isEmpty()) throw invalidCertificateChain("certificates must not be empty")
        chain.zipWithNext().forEach { (subject, issuer) ->
            if (subject.issuerDN != issuer.subjectDN || !isCertificateSignedBy(subject.der, issuer.der)) {
                throw invalidCertificateChain(
                    "certificates must be ordered leaf to root with each certificate signed by the one after it",
                )
            }
        }
        return chain
    }

    private fun invalidCertificateChain(message: String) =
        CertificateReferenceResolutionException(INVALID_CERTIFICATE_CHAIN, message)

    private suspend fun storeWithReservation(
        reservation: CertificateReferenceRecord,
        store: suspend () -> Unit,
    ) {
        // A thrown provider call can be ambiguous (the provider may have written before the
        // connection failed). Keep only the invisible tombstone; deleting by alias here could
        // remove an object that was not created by this operation.
        store()
        // If activation fails after a successful provider call, leave the object unindexed instead
        // of deleting by alias: CertificateStoreService has no create receipt or conditional delete.
        withContext(NonCancellable) {
            certificateReferenceRegistrar.activatePlatformManagedReservation(reservation).getOrThrowReference()
        }
    }

    private fun X509DistinguishedName.toSdk(): X509DistinguishedNameElements =
        X509DistinguishedNameElements(
            commonName = commonName ?: throw IllegalArgumentException("commonName is required"),
            country = country,
            state = state,
            locality = locality,
            organizationName = organizationName,
            organizationUnit = organizationUnit,
            email = email,
        )

    private fun CertificateSigningRequest.toRestResponse(): CertificateSigningRequestResponse =
        CertificateSigningRequestResponse(
            der = Base64ByteArray(der),
            commonName = commonName,
            organization = organization,
            organizationalUnit = organizationalUnit,
            locality = locality,
            state = state,
            country = country,
            email = email,
            serialNumber = serialNumber,
        )

    private fun com.sphereon.crypto.kms.rest.api.generated.models.CertificateSigningRequest.toSdk(): CertificateSigningRequest =
        CertificateSigningRequest(
            commonName = commonName,
            organization = organization,
            organizationalUnit = organizationalUnit,
            locality = locality,
            state = state,
            country = country,
            email = email,
            serialNumber = serialNumber,
            der = der.value,
        )

    private fun defaultNotAfter(): LocalDateTimeKMP =
        LocalDateTimeKMP.fromString(
            Clock.System
                .now()
                .toLocalDateTime(TimeZone.UTC)
                .date
                .plus(365, DateTimeUnit.DAY)
                .atTime(0, 0)
                .toString(),
        )

    private fun <T> IdkResult<T, IdkError>.getOrThrowReference(): T =
        getOrElse { error ->
            throw CertificateReferenceResolutionException(
                code = error.code,
                message = safeReferenceErrorMessage(error.code),
            )
        }

    /**
     * Registration errors from these codes carry messages written by the registrar and the
     * provider inspectors, never provider or persistence text, so they are passed on as the reason.
     */
    private fun registrationErrorMessage(error: IdkError): String =
        if (error.code in AUTHORED_REGISTRATION_ERROR_CODES) {
            error.message.defaultMessage?.takeIf { it.isNotBlank() } ?: safeReferenceErrorMessage(error.code)
        } else {
            safeReferenceErrorMessage(error.code)
        }

    private fun safeReferenceErrorMessage(code: String): String =
        when (code) {
            "NOT_FOUND_ERROR" -> "The certificate reference was not found"
            CertificateReferenceStoreErrorCodes.AMBIGUOUS_REFERENCE -> "The certificate reference is ambiguous"
            CertificateReferenceStoreErrorCodes.KEY_IDENTITY_MISMATCH -> "The certificate does not match the linked key"
            CertificateReferenceStoreErrorCodes.PROVIDER_DRIFT -> "The provider certificate no longer matches its registered reference"
            else -> "The certificate reference operation failed"
        }

    private fun CertificateReferenceRecord.toResponse(): CertificateReferenceResponse =
        CertificateReferenceResponse(
            id = id,
            alias = alias,
            providerId = providerId,
            providerCertificateId = providerCertificateId,
            kind = kind,
            source = source,
            controlMode = controlMode,
            origin = when (controlMode) {
                ResourceControlMode.PLATFORM_MANAGED -> Origin.MANAGED
                ResourceControlMode.EXTERNALLY_MANAGED -> Origin.EXTERNAL
            },
            linkedKeyReferenceId = linkedKeyReferenceId,
            certificateChain = certificateChainDer?.let {
                CertificateReferenceRecord.decodeCertificateChain(it).map(::Base64ByteArray)
            },
            certificateFingerprint = Base64ByteArray(certificateFingerprint),
            publicKeyFingerprint = Base64ByteArray(publicKeyFingerprint),
        )

    private suspend fun CertificateReferenceRecord.toMetadataResponse(): CertificateReferenceMetadataResponse {
        val linkedKey = certificateReferenceRegistrar.findLinkedKeyReference(this).getOrThrowReference()
        return CertificateReferenceMetadataResponse(
            id = id,
            alias = alias,
            providerId = providerId,
            providerCertificateId = providerCertificateId,
            kind = kind,
            source = source,
            controlMode = controlMode,
            origin = when (controlMode) {
                ResourceControlMode.PLATFORM_MANAGED -> Origin.MANAGED
                ResourceControlMode.EXTERNALLY_MANAGED -> Origin.EXTERNAL
            },
            linkedKeyReferenceId = linkedKeyReferenceId,
            linkedKeyAlias = linkedKey?.alias,
            linkedKeyKid = linkedKey?.kid,
            certificateFingerprint = Base64ByteArray(certificateFingerprint),
            publicKeyFingerprint = Base64ByteArray(publicKeyFingerprint),
        )
    }

    @ContributesTo(SessionScope::class)
    interface Graph {
        val certificatesRestService: CertificatesRestService
    }
}

internal const val INVALID_CERTIFICATE_CHAIN = "KMS_CERTIFICATE_CHAIN_INVALID"

private val AUTHORED_REGISTRATION_ERROR_CODES: Set<String> =
    setOf(
        "ILLEGAL_ARGUMENT_ERROR",
        INVALID_CERTIFICATE_CHAIN,
        "NOT_FOUND_ERROR",
        "KMS_PROVIDER_NOT_FOUND",
        "KMS_PROVIDER_NOT_AVAILABLE",
        "KMS_EXTERNAL_KEY_NOT_FOUND",
        "KMS_EXTERNAL_KEY_IDENTITY_MISMATCH",
        "KMS_CERTIFICATE_REFERENCE_MANAGED_STORE_CONFLICT",
        "KMS_PROVIDER_CERTIFICATE_REFERENCE_UNSUPPORTED",
        "KMS_PROVIDER_CERTIFICATE_IDENTITY_MISMATCH",
        CertificateReferenceStoreErrorCodes.KEY_IDENTITY_MISMATCH,
        CertificateReferenceStoreErrorCodes.REGISTRATION_CONFLICT,
        CertificateReferenceStoreErrorCodes.STORE_UNAVAILABLE,
        CertificateReferenceStoreErrorCodes.DURABLE_HISTORY_UNSUPPORTED,
    )
