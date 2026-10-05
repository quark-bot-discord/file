/** Thrown by downloadFile and fetchFile instead of storing or returning a file. */
export class FileWithheld extends Error {
    constructor(reason, stage) {
        super(`File withheld (${reason}) at ${stage}`);
        this.name = "FileWithheld";
        this.reason = reason;
        this.stage = stage;
    }
}
//# sourceMappingURL=withheld.js.map