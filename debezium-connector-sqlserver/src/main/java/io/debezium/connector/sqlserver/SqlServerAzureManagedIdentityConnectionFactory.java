/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.connector.sqlserver;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Properties;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.microsoft.sqlserver.jdbc.SQLServerDataSource;

/**
 * Factory for creating SQL Server connections with Azure Managed Identity authentication.
 * This class handles token caching and automatic refresh to support long-running connections.
 * 
 * @author Debezium Team
 */
public class SqlServerAzureManagedIdentityConnectionFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(SqlServerAzureManagedIdentityConnectionFactory.class);
    
    /**
     * Azure scope for SQL Server database authentication.
     * This is specific to Azure SQL Database and Azure SQL Managed Instance.
     */
    private static final String AZURE_SQL_DATABASE_SCOPE = "https://database.windows.net/.default";
    
    /**
     * Buffer time before token expiration to trigger refresh (5 minutes).
     * This ensures we refresh the token before it actually expires.
     */
    private static final Duration TOKEN_REFRESH_BUFFER = Duration.ofMinutes(5);
    
    /**
     * Timeout for token retrieval operations (30 seconds).
     */
    private static final Duration TOKEN_RETRIEVAL_TIMEOUT = Duration.ofSeconds(30);

    private final TokenCredential credential;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private AccessToken cachedToken;

    /**
     * Creates a new instance of the connection factory.
     */
    public SqlServerAzureManagedIdentityConnectionFactory() {
        this.credential = new DefaultAzureCredentialBuilder().build();
        LOGGER.info("Initialized Azure Managed Identity connection factory for SQL Server");
    }

    /**
     * Creates a SQL Server connection using Azure Managed Identity authentication.
     * 
     * @param url the JDBC connection URL
     * @param props the connection properties
     * @return a SQL Server connection authenticated with Azure Managed Identity
     * @throws SQLException if the connection cannot be established
     */
    public Connection createConnection(String url, Properties props) throws SQLException {
        LOGGER.debug("Creating SQL Server connection with Azure Managed Identity authentication");
        
        try {
            String token = getAccessToken();
            
            SQLServerDataSource dataSource = new SQLServerDataSource();
            dataSource.setURL(url);
            dataSource.setAccessToken(token);
            
            Connection conn = dataSource.getConnection();
            LOGGER.info("Successfully established SQL Server connection using Azure Managed Identity");
            return conn;
        }
        catch (Exception ex) {
            LOGGER.error("Failed to create SQL Server connection with Azure Managed Identity. " +
                        "Ensure that Azure Managed Identity is properly configured and the identity has the required permissions. " +
                        "For System Assigned Identity, verify it's enabled on the resource. " +
                        "For User Assigned Identity, verify the client ID is correctly configured.", ex);
            throw new SQLException("Failed to authenticate with Azure Managed Identity: " + ex.getMessage(), ex);
        }
    }

    /**
     * Gets a valid access token, using the cached token if it's still valid,
     * or fetching a new one if the cached token is expired or about to expire.
     * 
     * @return a valid access token string
     * @throws RuntimeException if token retrieval fails
     */
    private String getAccessToken() {
        // Check if we have a valid cached token with read lock
        lock.readLock().lock();
        try {
            if (isTokenValid(cachedToken)) {
                LOGGER.debug("Using cached Azure access token");
                return cachedToken.getToken();
            }
        }
        finally {
            lock.readLock().unlock();
        }

        // Need to fetch a new token, acquire write lock
        lock.writeLock().lock();
        try {
            // Double-check in case another thread already refreshed
            if (isTokenValid(cachedToken)) {
                LOGGER.debug("Using cached Azure access token (refreshed by another thread)");
                return cachedToken.getToken();
            }

            LOGGER.info("Fetching new Azure access token for SQL Server");
            TokenRequestContext requestContext = new TokenRequestContext().addScopes(AZURE_SQL_DATABASE_SCOPE);
            
            // Use block with timeout to avoid indefinite blocking
            // This call may throw a runtime exception if the timeout is exceeded
            // or if there's an authentication error from the Azure Identity service
            cachedToken = credential.getToken(requestContext)
                    .block(TOKEN_RETRIEVAL_TIMEOUT);
            
            if (cachedToken == null) {
                throw new RuntimeException("Failed to retrieve Azure access token: token is null");
            }
            
            LOGGER.info("Successfully retrieved Azure access token, expires at: {}", cachedToken.getExpiresAt());
            return cachedToken.getToken();
        }
        catch (Exception ex) {
            LOGGER.error("Error retrieving Azure access token from Azure Managed Identity. " +
                        "Verify that the managed identity has the required permissions (e.g., 'SQL DB Contributor' or 'db_datareader' role). " +
                        "For System Assigned Identity, ensure it's enabled. " +
                        "For User Assigned Identity, verify the AZURE_CLIENT_ID environment variable is set correctly.", ex);
            throw new RuntimeException("Failed to retrieve Azure access token: " + ex.getMessage(), ex);
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Checks if the given token is valid (non-null and not expired or about to expire).
     * 
     * @param token the token to check
     * @return true if the token is valid and has more than TOKEN_REFRESH_BUFFER time before expiration
     */
    private boolean isTokenValid(AccessToken token) {
        if (token == null || token.getExpiresAt() == null) {
            return false;
        }
        
        // Store expiry time in local variable for thread safety
        OffsetDateTime expiresAt = token.getExpiresAt();
        Instant now = Instant.now();
        Instant expiryThreshold = expiresAt.toInstant().minus(TOKEN_REFRESH_BUFFER);
        
        boolean isValid = now.isBefore(expiryThreshold);
        if (!isValid) {
            LOGGER.debug("Cached token is expired or about to expire (expires at: {})", expiresAt);
        }
        
        return isValid;
    }

    /**
     * Clears the cached token. This can be useful for testing or forcing a token refresh.
     */
    public void clearCachedToken() {
        lock.writeLock().lock();
        try {
            LOGGER.debug("Clearing cached Azure access token");
            cachedToken = null;
        }
        finally {
            lock.writeLock().unlock();
        }
    }
}
