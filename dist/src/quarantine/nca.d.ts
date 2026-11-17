/**
 * Reports to the NCA through the CSEA Industry Reporting Portal's submission
 * API (`POST /submission/api/referral/`, multipart: a `submission` JSON field
 * and the files as `uploadedFiles` parts), server to server: the file goes
 * from the quarantine to the NCA and is never downloaded by anyone.
 *
 *   NCA_API_KEY            the organisation's API key (X-API-KEY)
 *   NCA_ORG_ID             the organisation's UUID (orgId header, reportingEsp)
 *   NCA_API_URL            default https://www.uk-child-sexual-abuse-industry-reporting.gov.uk/submission
 *   NCA_REPORTER_FIRST_NAME, NCA_REPORTER_LAST_NAME, NCA_REPORTER_EMAIL,
 *   NCA_REPORTER_PHONE, NCA_REPORTER_PHONE_CC (default +44)
 *                          the person the NCA contacts (Schedule 1, item 1)
 *   NCA_ESP_NAME           default "Quark Bot Limited"
 *
 * `ncaPayload` maps the report's fields (`reportFieldsOf`) onto the API's
 * SubmissionPayload; everything else Quark holds goes with it as a JSON
 * document, so nothing in Schedule 1 is left out for want of a field.
 */
import type { Priority, QuarantineItem, reportFieldsOf } from "./index.js";
export declare const DEFAULT_NCA_API_URL = "https://www.uk-child-sexual-abuse-industry-reporting.gov.uk/submission";
export interface NcaConfig {
    apiKey: string;
    orgId: string;
    baseUrl: string;
    espName: string;
    reporter: {
        firstName: string;
        lastName: string;
        email: string;
        phone: string;
        phoneCountryCode: string;
    };
    fetchImpl?: typeof fetch;
    /** Tests only: the roots trusted when the server's chain has to be completed. */
    rootCertificates?: readonly string[];
}
/** The API's settings, or undefined while any is missing. */
export declare function ncaConfigFromEnv(env?: NodeJS.ProcessEnv): NcaConfig | undefined;
export declare function priorityIdOf(level: Priority | null | undefined): "1" | "2" | "3";
/** How the content came to light, in the API's words. */
export type DetectionMethod = "A user of the platform" | "A third party reporter" | "An automated detection tool" | "An employee moderating the platform";
export declare function methodOf(item: QuarantineItem): DetectionMethod;
/** A phone number as the schema's "digits", with its calling code apart if given. */
export declare function phoneOf(raw: string, defaultCode?: string): {
    countryCallingCode: string;
    value: string;
};
type Fields = ReturnType<typeof reportFieldsOf>;
/**
 * The SubmissionPayload for one item. `previousReferences` are the NCA
 * references of earlier reports this one relates to.
 */
export declare function ncaPayload(item: QuarantineItem, fields: Fields, config: NcaConfig): {
    about: string;
    priorityId: "1" | "2" | "3";
    potentialMemeReport: boolean;
    reportedInformation: {
        incidentSummary: {
            espEscalation: string;
            humanModerator: boolean;
            incidentDateTime: string;
            incidentType: string;
            materialAltered: boolean;
            methodOfDetection: DetectionMethod;
            additionalInfo: string;
            relatedPreviousReferrals: string;
            additionalDocuments: never[];
        };
        additionalInformation: {
            value: string;
        }[];
        incidentDetails: {
            chatIncident: {
                screenName: string;
                chatRoomName: string;
            }[];
        };
        intendedRecipients: {
            intendedRecipient: never[];
        };
        lawEnforcementInformation: {
            caseNumber: string;
            reportedToLawEnforcement: boolean;
        };
        reportedPeople: {
            reportedPerson: {
                firstName: string;
                middleName: string;
                lastName: string;
                senderStatus: string;
                screenName: string;
                espUserId: string;
                ipAddress: string;
                dateOfBirth: string;
                billingDateOfBirth: string;
                billingName: string;
                dateAccountClosed: string;
                accountClosed: boolean;
                userNotifiedOfAccountcloser: boolean;
                profileUrl: string[];
                additionalEmails: never[];
                emails: {
                    email: {
                        value: string;
                        verified: boolean;
                        verificationDate: string;
                    }[];
                };
                phones: {
                    phone: {
                        verified: boolean;
                        verificationDate: string;
                        countryCallingCode: string;
                        value: string;
                    }[];
                };
                addresses: {
                    address: never[];
                };
                billingAddress: {
                    address: Record<string, string>[];
                };
                recoveryEmail: {
                    email: {
                        value: string;
                    }[];
                };
                recoveryPhoneNumber: {
                    phone: never[];
                };
                sourceInformation: {
                    sourceCapture: never[];
                };
                additionalInformation: {
                    value: string;
                }[];
                bankAccountDetails: string;
                onlinePaymentPlatformDetails: string;
                creditCardDetails: string;
                otherAccountsLinkedToUser: string;
                recoveryAccount: string;
                fraudulentAccountReason: string;
                additionalUsernames: string;
                passportNumber: string;
                niNumber: string;
                drivingLicense: string;
                bio: string;
                profilePictureAttached: boolean;
                biometricDataAttached: boolean;
                voiceRecordingsAttached: boolean;
                idUploadAttached: boolean;
                userProvidedIdentificationRadio: boolean;
            }[];
        };
        reportingEsp: {
            espName: string;
            organisationId: string;
            platform: string;
            firstName: string;
            lastName: string;
            phones: {
                phone: {
                    countryCallingCode: string;
                    value: string;
                }[];
            };
            emails: {
                email: {
                    value: string;
                }[];
            };
        };
        uploadedFiles: {
            uploadedFile: {
                originalFilename: string;
                uploadedDateTime: string;
                ipAddress: string;
                potentialMeme: boolean;
                links: {
                    link: {
                        href: string;
                        rel: string;
                    }[];
                };
                originalFileHashes: {
                    originalFileHash: {
                        value: string;
                    }[];
                };
                sourceInformation: {
                    sourceCapture: never[];
                };
                additionalInformation: {
                    value: string;
                }[];
            }[];
        };
    };
};
export interface NcaResult {
    referralID: string;
    referralFriendlyID: string;
    reportID?: number;
}
/**
 * What a failed attempt means for trying again:
 * - `retry`: the NCA certainly did not process it (no connection was made,
 *   or it answered 408, 429 or 503). Tried again automatically.
 * - `refused`: the NCA rejected the report (400, 404, 413, 415, 422 and other
 *   client errors). Trying again unchanged will not help.
 * - `uncertain`: it may have been received: a 5xx except 503, a dropped
 *   connection, a timeout, or a 2xx without a referral number. Not tried
 *   again, so it is not reported twice: check the portal first.
 *
 * 401 and 403 count as `refused`. The NCA's API checks the key before the
 * report, and until its next release answers 401 when the real problem is the
 * report's data mapping (NCA support, 16/11/2026); either way nothing was
 * received, and retrying unchanged will not help.
 */
export type NcaFailureKind = "retry" | "refused" | "uncertain";
export declare function kindOfStatus(status: number): NcaFailureKind;
export declare class NcaError extends Error {
    readonly status: number;
    readonly body: string;
    readonly kind: NcaFailureKind;
    constructor(status: number, body: string, kind?: NcaFailureKind);
    /** Not tried again automatically. */
    get permanent(): boolean;
}
/** A failure before anything was sent (e.g. completing the certificate chain). */
export declare class NcaNotSentError extends Error {
    readonly cause?: unknown | undefined;
    constructor(message: string, cause?: unknown | undefined);
}
/** How to treat any error from `submitReferral`. */
export declare function ncaFailureKind(error: unknown): NcaFailureKind;
/** The intermediate that issued `host`'s certificate, as PEM, from its CA Issuers address. */
export declare function intermediateFor(host: string, port?: number, fetchImpl?: typeof fetch): Promise<string>;
/** How the `submission` field is encoded: plain text (as NCA support asked), or a JSON part. */
export type SubmissionEncoding = "text" | "json";
/** One POST to the referral endpoint; the raw answer, whatever its status. */
export declare function postReferral(config: NcaConfig, payload: unknown, files: {
    name: string;
    type: string;
    bytes: Buffer;
}[], encoding?: SubmissionEncoding): Promise<{
    status: number;
    ok: boolean;
    body: string;
}>;
/** POSTs one referral. The file and the JSON document go as `uploadedFiles`. */
export declare function submitReferral(config: NcaConfig, payload: unknown, files: {
    name: string;
    type: string;
    bytes: Buffer;
}[], encoding?: SubmissionEncoding): Promise<NcaResult>;
/** One probe of `checkWithNca`. */
export interface NcaProbe {
    step: string;
    sent: string;
    status: number | null;
    body: string;
    meaning: string;
}
/**
 * Find out, without reporting anything, whether the NCA accepts the key and
 * can read a report. Every probe is invalid on purpose, so none can create a
 * referral, and none carries the reported file:
 *  1. `{}` (missing required fields): 400 means the key is good; 401, the key.
 *  2. The real report with priorityId "0" and no files, as text, then
 *  3. as a JSON part: a 400 listing errors means the NCA read it (the list is
 *     what to fix besides the priority); a 401 means it could not read it.
 *  4. As 2, with quark-report.json attached: does the extra file break it?
 * Until the NCA's next release a 401 also stands for "could not read the data".
 */
export declare function probeNca(config: NcaConfig, payload: Record<string, unknown>, reportJson: {
    name: string;
    type: string;
    bytes: Buffer;
}): Promise<NcaProbe[]>;
export {};
