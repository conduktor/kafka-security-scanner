package io.kafkascanner.collectors;

import java.time.Duration;
import java.util.Map;
import org.apache.kafka.clients.admin.AdminClient;
import org.checkerframework.checker.nullness.qual.Nullable;

/** Shared configuration passed to every collector. */
public record CollectorContext(
    String bootstrap,
    Duration timeout,
    @Nullable AdminClient adminClient,
    @Nullable String kafkaConfigDir,
    @Nullable String jmxHostPort,
    @Nullable String connectUrl,
    @Nullable String schemaRegistryUrl,
    @Nullable String restProxyUrl,
    @Nullable String docsDir,
    @Nullable String prometheusUrl,
    @Nullable String zkAdminHostPort,
    @Nullable String consumerJmxHostPorts,
    @Nullable String ccApiKey,
    @Nullable String ccApiSecret,
    @Nullable String ccClusterId,
    @Nullable String awsRegion,
    @Nullable String awsMskClusterArn,
    @Nullable String cisReportPath,
    @Nullable String aivenToken,
    @Nullable String aivenProject,
    @Nullable String aivenService,
    @Nullable String rpToken,
    @Nullable String rpClusterId,
    @Nullable String azureToken,
    @Nullable String azureSubscriptionId,
    @Nullable String azureResourceGroup,
    @Nullable String azureNamespace,
    @Nullable String k8sNamespace,
    @Nullable String gcpToken,
    @Nullable String gcpProject,
    @Nullable String streamsJmxHostPorts,
    @Nullable String streamsStateDir,
    Map<String, String> saslProps,
    String kafkaFlavor
) {
    public boolean hasAdminClient() {
        return adminClient != null;
    }

    public boolean hasKafkaConfigDir() {
        return kafkaConfigDir != null && !kafkaConfigDir.isBlank();
    }

    public boolean hasJmx() {
        return jmxHostPort != null && !jmxHostPort.isBlank();
    }

    public boolean hasConnectUrl() {
        return connectUrl != null && !connectUrl.isBlank();
    }

    public boolean hasSchemaRegistryUrl() {
        return schemaRegistryUrl != null && !schemaRegistryUrl.isBlank();
    }

    public boolean hasRestProxyUrl() {
        return restProxyUrl != null && !restProxyUrl.isBlank();
    }

    public boolean hasDocsDir() {
        return docsDir != null && !docsDir.isBlank();
    }

    public boolean hasPrometheusUrl() {
        return prometheusUrl != null && !prometheusUrl.isBlank();
    }

    public boolean hasZkAdminHostPort() {
        return zkAdminHostPort != null && !zkAdminHostPort.isBlank();
    }

    public boolean hasConsumerJmxHostPorts() {
        return consumerJmxHostPorts != null && !consumerJmxHostPorts.isBlank();
    }

    public boolean hasCcCreds() {
        return ccApiKey != null && !ccApiKey.isBlank()
            && ccApiSecret != null && !ccApiSecret.isBlank();
    }

    public boolean hasAwsConfig() {
        return (awsRegion != null && !awsRegion.isBlank())
            || (awsMskClusterArn != null && !awsMskClusterArn.isBlank());
    }

    public boolean hasCisReport() {
        return cisReportPath != null && !cisReportPath.isBlank();
    }

    public boolean hasAivenToken() {
        return aivenToken != null && !aivenToken.isBlank();
    }

    public boolean hasRpToken() {
        return rpToken != null && !rpToken.isBlank();
    }

    public boolean hasAzureToken() {
        return azureToken != null && !azureToken.isBlank();
    }

    public boolean hasK8sNamespace() {
        return k8sNamespace != null && !k8sNamespace.isBlank();
    }

    public boolean hasGcpToken() {
        return gcpToken != null && !gcpToken.isBlank();
    }
}
