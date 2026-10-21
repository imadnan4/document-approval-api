'use strict';

class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }

  toBody() {
    const error = { code: this.code, message: this.message };
    if (this.details) error.details = this.details;
    return { error };
  }
}

const badRequest = (code, message, details) =>
  new ApiError(400, code, message, details);
const forbidden = (code, message) => new ApiError(403, code, message);
const notFound = (code, message) => new ApiError(404, code, message);
const conflict = (code, message, details) =>
  new ApiError(409, code, message, details);

module.exports = { ApiError, badRequest, forbidden, notFound, conflict };
