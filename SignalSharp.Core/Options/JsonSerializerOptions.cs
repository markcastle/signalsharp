using SignalSharp.Core.Interfaces;

namespace SignalSharp.Core.Options
{
    /// <summary>
    /// Default implementation of IJsonSerializerOptions.
    /// </summary>
    public class JsonSerializerOptions : IJsonSerializerOptions
    {
        /// <inheritdoc/>
        public bool IgnoreNullValues { get; set; } = true;

        /// <inheritdoc/>
        public bool UseCamelCase { get; set; } = true;

        /// <inheritdoc/>
        public bool HandleReferences { get; set; } = false;

        /// <inheritdoc/>
        public bool WriteIndented { get; set; } = false;

        /// <inheritdoc/>
        public bool AllowTrailingCommas { get; set; } = false;

        /// <inheritdoc/>
        public bool AllowComments { get; set; } = false;
    }
} 