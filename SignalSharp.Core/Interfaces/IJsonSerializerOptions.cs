namespace SignalSharp.Core.Interfaces
{
    /// <summary>
    /// Interface for JSON serializer options.
    /// </summary>
    public interface IJsonSerializerOptions
    {
        /// <summary>
        /// Gets or sets whether to ignore null values during serialization.
        /// </summary>
        bool IgnoreNullValues { get; set; }

        /// <summary>
        /// Gets or sets whether to use camel case for property names.
        /// </summary>
        bool UseCamelCase { get; set; }

        /// <summary>
        /// Gets or sets whether to handle references during serialization.
        /// </summary>
        bool HandleReferences { get; set; }

        /// <summary>
        /// Gets or sets whether to write indented JSON.
        /// </summary>
        bool WriteIndented { get; set; }

        /// <summary>
        /// Gets or sets whether to allow trailing commas.
        /// </summary>
        bool AllowTrailingCommas { get; set; }

        /// <summary>
        /// Gets or sets whether to allow comments in JSON.
        /// </summary>
        bool AllowComments { get; set; }
    }
} 