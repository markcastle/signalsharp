using System;

namespace SignalSharp.Core.Exceptions
{
    /// <summary>
    /// Exception thrown when a requested session is not found.
    /// </summary>
    public class SessionNotFoundException : Exception
    {
        /// <summary>
        /// Gets the ID of the session that was not found.
        /// </summary>
        public string SessionId { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionNotFoundException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="sessionId">The ID of the session that was not found.</param>
        public SessionNotFoundException(string message, string sessionId)
            : base(message)
        {
            SessionId = sessionId;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionNotFoundException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="sessionId">The ID of the session that was not found.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public SessionNotFoundException(string message, string sessionId, Exception innerException)
            : base(message, innerException)
        {
            SessionId = sessionId;
        }
    }
} 