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
                        value: string;
                        countryCallingCode: string;
                        verified: boolean;
                        verificationDate: string;
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
export declare class NcaError extends Error {
    readonly status: number;
    readonly body: string;
    /** 400: the report itself is wrong; trying again will not help. */
    readonly permanent: boolean;
    constructor(status: number, body: string, 
    /** 400: the report itself is wrong; trying again will not help. */
    permanent: boolean);
}
/** The intermediate that issued `host`'s certificate, as PEM, from its CA Issuers address. */
export declare function intermediateFor(host: string, port?: number, fetchImpl?: typeof fetch): Promise<string>;
/** POSTs one referral. The file and the JSON document go as `uploadedFiles`. */
export declare function submitReferral(config: NcaConfig, payload: unknown, files: {
    name: string;
    type: string;
    bytes: Buffer;
}[]): Promise<NcaResult>;
export {};
