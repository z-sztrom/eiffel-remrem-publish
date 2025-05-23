/*
    Copyright 2018 Ericsson AB.
    For a full list of individual contributors, please see the commit history.
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
package com.ericsson.eiffel.remrem.publish.helper;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeoutException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.LoggerFactory;

import com.ericsson.eiffel.remrem.publish.config.PropertiesConfig;
import com.ericsson.eiffel.remrem.publish.exception.NackException;
import com.ericsson.eiffel.remrem.publish.exception.RemRemPublishException;
import com.rabbitmq.client.AMQP.BasicProperties;
import com.rabbitmq.client.AlreadyClosedException;
import com.rabbitmq.client.BlockedListener;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.MessageProperties;
import com.rabbitmq.client.ShutdownListener;
import com.rabbitmq.client.ShutdownSignalException;

import ch.qos.logback.classic.Logger;

public class RabbitMqProperties {

    private RMQBeanConnectionFactory factory = new RMQBeanConnectionFactory();
    private static final Random random = new Random();
    private boolean usePersitance = true;

    private String host;
    private String exchangeName;
    private Integer port;
    private String tlsVer;
    private String virtualHost;
    private String username;
    private String password;
    private String domainId;
    private Integer channelsCount;
    private boolean createExchangeIfNotExisting;
    private String routingKeyTypeOverrideFilePath;
    private Integer tcpTimeOut;
    private String uri;
    private URI parsedUri;
    private boolean hasExchange = false;
//  built in tcp connection timeout value for MB in milliseconds.
    public static final Integer DEFAULT_TCP_TIMEOUT = 60000;
    private Long waitForConfirmsTimeOut;
    public static final Long DEFAULT_WAIT_FOR_CONFIRMS_TIMEOUT = 5000L;
    public static final Integer DEFAULT_CHANNEL_COUNT = 1;
    public static final String CONTENT_TYPE = "application/json";
    public static final String ENCODING_TYPE = "UTF-8";
    public static final BasicProperties PERSISTENT_BASIC_APPLICATION_JSON;
    public static final String SEMANTICS_MESSAGE_PROTOCOL = "eiffelsemantics";

    private Connection rabbitConnection;
    private String protocol;

    private List<Channel> rabbitChannels;

    private ResourceBundle types;
    private final String TYPE = "type";
    private final String DOT = ".";

    Logger log = (Logger) LoggerFactory.getLogger(RMQHelper.class);

    static {
        PERSISTENT_BASIC_APPLICATION_JSON =
                MessageProperties.PERSISTENT_BASIC.builder()
                        .contentType(CONTENT_TYPE)
                        .contentEncoding(ENCODING_TYPE)
                        .build();
    }

    public Long getWaitForConfirmsTimeOut() {
        return waitForConfirmsTimeOut;
    }

    public void setWaitForConfirmsTimeOut(Long waitForConfirmsTimeOut) {
        this.waitForConfirmsTimeOut = waitForConfirmsTimeOut;
    }

    public String getHost() {
        if (host != null)
            return host;

        if (parsedUri != null)
            return parsedUri.getHost();

        return null;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getExchangeName() {
        return exchangeName;
    }

    public void setExchangeName(String exchangeName) {
        if (!exchangeName.equals(this.exchangeName)) {
            this.exchangeName = exchangeName;
            this.hasExchange = false;
        }
    }

    public Integer getPort() {
        if (port != null)
            return port;

        if (parsedUri != null)
            return parsedUri.getPort();

        return null;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public String getVirtualHost() { return virtualHost; }

    public void setVirtualHost(String virtualHost) { this.virtualHost = virtualHost; }

    public String getTlsVer() {
        return tlsVer;
    }

    public void setTlsVer(String tlsVer) {
        this.tlsVer = tlsVer;
    }

    public String getUsername() {
        if (username != null)
            return username;

        return parseUserInfoFromUri(0 /* password is at index 1 */);
    }

    public void setUsername(String user) {
        this.username = user;
    }

    private String parseUserInfoFromUri(int index) {
        if (parsedUri == null)
            parsedUri = URI.create(uri);

        String userInfo = parsedUri.getUserInfo();
        if (userInfo != null) {
            String[] usernameAndPassword = userInfo.split(":");
            if (usernameAndPassword.length > index)
                return usernameAndPassword[index];
        }

        return null;
    }

    public String getPassword() {
        if (password != null)
            return password;

        return parseUserInfoFromUri(1 /* password is at index 1 */);
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getDomainId() {
        return domainId;
    }

    public void setDomainId(String domainId) {
        this.domainId = domainId;
    }

    public boolean isCreateExchangeIfNotExisting() {
        return createExchangeIfNotExisting;
    }

    public void setCreateExchangeIfNotExisting(boolean createExchangeIfNotExisting) {
        this.createExchangeIfNotExisting = createExchangeIfNotExisting;
    }

    public String getRoutingKeyTypeOverrideFilePath() {
	return routingKeyTypeOverrideFilePath;
    }

    public void setRoutingKeyTypeOverrideFilePath(String routingKeyTypeOverrideFilePath) {
	this.routingKeyTypeOverrideFilePath = routingKeyTypeOverrideFilePath;
    }

    public Integer getChannelsCount() {
        return channelsCount;
    }

    public void setChannelsCount(Integer channelsCount) {
        this.channelsCount = channelsCount;
    }

    public Integer getTcpTimeOut() {
        return tcpTimeOut;
    }

    public void setTcpTimeOut(Integer tcpTimeOut) {
        this.tcpTimeOut = tcpTimeOut;
    }

    public RMQBeanConnectionFactory getFactory() {
        return factory;
    }

    public void setFactory(RMQBeanConnectionFactory factory) {
        this.factory = factory;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public Connection getRabbitConnection() {
        return rabbitConnection;
    }

    public void setRabbitConnection(Connection rabbitConnection) {
        this.rabbitConnection = rabbitConnection;
    }

    public void init() {
        log.info("RabbitMqProperties init ...");
        if (Boolean.getBoolean(PropertiesConfig.CLI_MODE)) {
            initCli();
        } else {
            initService();
        }

        try {
            if (uri != null) {
                factory.setUri(uri);
            }

            if (host != null) {
                factory.setHost(host);
                log.info("Host address: " + host);
            }

            if (port != null) {
                factory.setPort(port);
                log.info("Port is: " + port);
            } else {
                log.info("Using default rabbit mq port.");
            }

            if (virtualHost != null && !virtualHost.isEmpty()) {
                factory.setVirtualHost(virtualHost);
                log.info("Virtual host is: " + virtualHost);
            } else {
                log.info("Using default virtual host");
            }

            log.info("Exchange is: " + exchangeName);

            if((username != null && !username.isEmpty()) && (password != null && !password.isEmpty())) {
                factory.setUsername(username);
                factory.setPassword(password);
            }

            if (tlsVer != null && !tlsVer.isEmpty()) {
                if (tlsVer.contains("default")) {
                    log.info("Using default TLS version connection to RabbitMQ.");
                    factory.useSslProtocol();
                }
                else {
                    log.info("Using TLS version " + tlsVer + " connection to RabbitMQ.");
                    factory.useSslProtocol("TLSv" + tlsVer);
                }
            }
            else{
                log.info("Using standard connection method to RabbitMQ.");
            }

            madatoryParametersCheck();
        } catch (KeyManagementException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        } catch (URISyntaxException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
        try {
            //The exception can be safely handled here as there is a check for existence of exchange is done before each publish.
            checkAndCreateExchangeIfNeeded();
        } catch (RemRemPublishException e) {
            log.error("Error occurred while setting up the RabbitMq Connection. "+e.getMessage());
            e.printStackTrace();
        }

        if (StringUtils.isNotBlank(routingKeyTypeOverrideFilePath)) {
            try {
                types = new PropertyResourceBundle(new FileInputStream(routingKeyTypeOverrideFilePath));
            } catch (IOException e) {
                log.error("Cannot find routing key file. "+e.getMessage());
            }
        }
    }

    /**
     * This method is used to create Rabbitmq connection and channels
     * @throws RemRemPublishException
     */
    public void createRabbitMqConnection() throws RemRemPublishException {
        try {
            if (tcpTimeOut == null || tcpTimeOut == 0) {
                tcpTimeOut = DEFAULT_TCP_TIMEOUT;
            }
            factory.setConnectionTimeout(tcpTimeOut);
            rabbitConnection = factory.newConnection();
            rabbitConnection.addShutdownListener(new ShutdownListener() {
                @Override
                public void shutdownCompleted(ShutdownSignalException cause) {
                    log.debug("Connection Shutdown completed " + cause.getMessage());
                    try {
                        rabbitConnection.close();
                    } catch (AlreadyClosedException | IOException e) {
                        // This is intentionally added, if we do not call the close function, connection is not closed properly
                        // and the connections count is getting increased..
                    }
                }
            });

            rabbitConnection.addBlockedListener(new BlockedListener() {
                public void handleBlocked(String reason) throws IOException {
                    // Connection is now blocked
                    log.debug("Connection is blocked " + reason);
                }

                public void handleUnblocked() throws IOException {
                    // Connection is now unblocked
                }
            });
            log.info("Connected to RabbitMQ.");
            rabbitChannels = new ArrayList<>();
            if(channelsCount == null || channelsCount == 0 ) {
                channelsCount = DEFAULT_CHANNEL_COUNT;
            }
            for (int i = 0; i < channelsCount; i++) {
                createNewChannel();
            }
        } catch (IOException | TimeoutException e) {
            log.error(e.getMessage(), e);
            throw new RemRemPublishException("Failed to create connection for Rabbitmq :: ", factory,
                    e);
        }
    }

    /**
     * This method is used to create Rabbitmq channels
     * @throws IOException
     */
    private Channel createNewChannel() throws IOException {
        Channel channel = rabbitConnection.createChannel();
        channel.addShutdownListener(new ShutdownListener() {
            public void shutdownCompleted(ShutdownSignalException cause) {
                // Beware that proper synchronization is needed here
                if (cause.isInitiatedByApplication()) {
                    log.info("Shutdown of MB channel is initiated by application; ignoring it: "
                            + cause.getMessage());
                } else {
                    log.error("Shutdown of MB channel is NOT initiated by application: "
                            + cause.getMessage());
                    boolean cliMode = Boolean.getBoolean(PropertiesConfig.CLI_MODE);
                    if (cliMode) {
                        System.exit(-3);
                    }
                }
            }
        });
        channel.confirmSelect();
        rabbitChannels.add(channel);
        return channel;
    }
    
    private void initCli() {
        setValues();
    }

    private void initService() {
        if (host == null) {
            host = getValuesFromSystemProperties(protocol + ".rabbitmq.host");
        }

        if (port == null) {
            port = Integer.getInteger(getValuesFromSystemProperties(protocol + ".rabbitmq.port"));
        }

        if (virtualHost == null) {
            virtualHost = getValuesFromSystemProperties(protocol + ".rabbitmq.virtualHost");
        }

        if (domainId == null) {
            domainId = getValuesFromSystemProperties(protocol + ".rabbitmq.domainId");
        }

        if (tlsVer == null) {
            tlsVer = getValuesFromSystemProperties(protocol + ".rabbitmq.tls");
        }

        if (exchangeName == null) {
            exchangeName = getValuesFromSystemProperties(protocol + ".rabbitmq.exchangeName");
        }

        if (username == null) {
            username = getValuesFromSystemProperties(protocol + ".rabbitmq.username");
        }

        if (password == null) {
            password = getValuesFromSystemProperties(protocol + ".rabbitmq.password");
        }

        if (channelsCount == null ) {
            channelsCount = Integer.getInteger(getValuesFromSystemProperties(protocol + ".rabbitmq.channelsCount"));
        }

        if (tcpTimeOut == null) {
            tcpTimeOut = Integer.getInteger(getValuesFromSystemProperties(protocol + ".rabbitmq.tcpTimeOut"));
        }
        
        if (waitForConfirmsTimeOut == null ) {
            waitForConfirmsTimeOut = Long.getLong(getValuesFromSystemProperties(protocol + ".rabbitmq.waitForConfirmsTimeOut"));
        }

        if (protocol.equalsIgnoreCase(SEMANTICS_MESSAGE_PROTOCOL) 
                && (routingKeyTypeOverrideFilePath == null || routingKeyTypeOverrideFilePath.isBlank())) {
            routingKeyTypeOverrideFilePath = getValuesFromSystemProperties(PropertiesConfig.SEMANTICS_ROUTINGKEY_TYPE_OVERRIDE_FILEPATH);
        }
        
    }
    

    private void setValues() {
        host = getValuesFromSystemProperties(PropertiesConfig.MESSAGE_BUS_HOST);
        port = Integer.getInteger(PropertiesConfig.MESSAGE_BUS_PORT);
        virtualHost = getValuesFromSystemProperties(PropertiesConfig.VIRTUAL_HOST);
        domainId = getValuesFromSystemProperties(PropertiesConfig.DOMAIN_ID);
        channelsCount = Integer.getInteger(PropertiesConfig.CHANNELS_COUNT);
        waitForConfirmsTimeOut = Long.getLong(PropertiesConfig.WAIT_FOR_CONFIRMS_TIME_OUT);
        tlsVer = getValuesFromSystemProperties(PropertiesConfig.TLS);
        exchangeName = getValuesFromSystemProperties(PropertiesConfig.EXCHANGE_NAME);
        usePersitance = Boolean.getBoolean(PropertiesConfig.USE_PERSISTENCE);
        createExchangeIfNotExisting = Boolean.parseBoolean(getValuesFromSystemProperties(PropertiesConfig.CREATE_EXCHANGE_IF_NOT_EXISTING));
        tcpTimeOut = Integer.getInteger(PropertiesConfig.TCP_TIMEOUT);
        routingKeyTypeOverrideFilePath = getValuesFromSystemProperties(PropertiesConfig.SEMANTICS_ROUTINGKEY_TYPE_OVERRIDE_FILEPATH);
        username = getValuesFromSystemProperties(PropertiesConfig.USERNAME);
        password = decryptString(getValuesFromSystemProperties(PropertiesConfig.PASSWORD));
        uri = getValuesFromSystemProperties(PropertiesConfig.URI);
        if (!StringUtils.isBlank(uri))
            parsedUri = URI.create(uri);
    }

    private String decryptString(String password) {
        if (password == null)
            return null;

        return new String(Base64.getDecoder().decode(password));
    }

    private String getValuesFromSystemProperties(String propertyName) {
        return System.getProperty(propertyName);
    }

    /**
     * This method is used to check mandatory RabbitMQ properties.
     */
    private void madatoryParametersCheck() {
        if (factory == null) {
            throw new RuntimeException("Missing RabbitMQ factory intialization");
        }

        if (StringUtils.isBlank(host) && StringUtils.isBlank(factory.getHost())) {
            throw new RuntimeException("Missing host name");
        }

        if (StringUtils.isBlank(exchangeName)) {
            throw new RuntimeException("Missing exchange name");
        }
    }

    /**
     * This method is used to check for checking exchange availability, if
     * exchange is not available creates a new exchange based on isCreateExchangeIfNotExisting true boolean property  .
     * @throws RemRemPublishException
     * @throws TimeoutException
     * @throws IOException
     */
    public void checkAndCreateExchangeIfNeeded() throws RemRemPublishException {
        final boolean exchangeAlreadyExist = hasExchange();
        if (!exchangeAlreadyExist) {
            if (isCreateExchangeIfNotExisting()) {
                Connection connection = null;
                try {
                    connection = factory.newConnection();
                } catch (final IOException | TimeoutException e) {
                    throw new RemRemPublishException(
                            "Exception occurred while creating Rabbitmq connection :: ", factory, e);
                }
                Channel channel = null;
                try {
                    channel = connection.createChannel();
                } catch (final IOException e) {
                    throw new RemRemPublishException(
                            "Exception occurred while creating Channel with Rabbitmq connection ::",
                            factory, e);
                }
                try {
                    channel.exchangeDeclare(exchangeName, "topic", true);
                    log.info("Exchange {} is created",exchangeName);
                    hasExchange = true;
                } catch (final IOException e) {
                    log.info(exchangeName + "failed to create an exchange");
                    throw new RemRemPublishException(
                            "Unable to create Exchange with Rabbitmq connection " + exchangeName,
                            factory, e);
                } finally {
                    if (channel == null || channel.isOpen()) {
                        try {
                            channel.close();
                            connection.close();
                        } catch (IOException | TimeoutException e) {
                            log.warn("Exception occurred while closing the channel" + e.getMessage());
                        }
                    }
                }
            } else {
                if (!Boolean.getBoolean(PropertiesConfig.CLI_MODE)) {
                    throw new RemRemPublishException(exchangeName + PropertiesConfig.INVALID_EXCHANGE_MESSAGE_SERVICE);
                } else {
                    throw new RemRemPublishException("Exchange " + exchangeName + PropertiesConfig.INVALID_EXCHANGE_MESSAGE_CLI);
                }
            }
        }
    }

    /**
     * This method is used to check exchange exists or not
     * @return Boolean
     * @throws RemRemPublishException
     * @throws TimeoutException
     * @throws IOException
     */
    private boolean hasExchange() throws RemRemPublishException {
        if(hasExchange) {
           log.info("Exchange is: {}", exchangeName);
           return true;
        }

        Connection connection;
        try {
            connection = factory.newConnection();
        } catch (final IOException | TimeoutException e) {
            throw new RemRemPublishException(
                    "Exception occurred while creating Rabbitmq connection :: ", factory, e);
        }
        Channel channel = null;
        try {
            channel = connection.createChannel();
        } catch (final IOException e) {
            throw new RemRemPublishException(
                    "Exception occurred while creating Channel with Rabbitmq connection :: ",
                    factory, e);
        }
        try {
            channel.exchangeDeclarePassive(exchangeName);
            hasExchange = true;
            return hasExchange;
        } catch (final IOException e) {
            log.info("Exchange " + exchangeName + " was not created");
            return false;
        } finally {
            if (channel != null && channel.isOpen()) {
                try {
                    channel.close();
                    connection.close();
                } catch (IOException | TimeoutException e) {
                    log.warn("Exception occurred while closing the channel" + e.getMessage());
                }
            }
        }
    }


	/**
     * This method is used to publish the message to RabbitMQ
     * @param routingKey
     * @param msg is Eiffel Event
     * @throws IOException
     * @throws NackException
     * @throws TimeoutException
     * @throws RemRemPublishException
     */
    public void send(String routingKey, String msg, String eventId)
            throws IOException, NackException, TimeoutException, RemRemPublishException, IllegalArgumentException {
            Channel channel = giveMeRandomChannel();
            checkAndCreateExchangeIfNeeded();

            BasicProperties msgProps = usePersitance ? PERSISTENT_BASIC_APPLICATION_JSON
                    : MessageProperties.BASIC;

        try {
            long publishStartTime = System.nanoTime();
            channel.basicPublish(exchangeName, routingKey, msgProps, msg.getBytes());
            long publishEndTime = System.nanoTime();
            long diff = publishEndTime - publishStartTime;
            Duration durationInNanos = Duration.ofNanos(diff);
            String duration = String.format("%d:%02d:%02d.%03d",
                    durationInNanos.toHours(),
                    durationInNanos.toMinutesPart(),
                    durationInNanos.toSecondsPart(),
                    durationInNanos.toMillisPart());
            log.info("Published message {} with size {} bytes on exchange '{}' with routing key '{}' with the duration of '{}'", eventId,
                    msg.getBytes().length, exchangeName, routingKey, duration);
            if (waitForConfirmsTimeOut == null || waitForConfirmsTimeOut == 0) {
                waitForConfirmsTimeOut = DEFAULT_WAIT_FOR_CONFIRMS_TIMEOUT;
            }
            channel.waitForConfirmsOrDie(waitForConfirmsTimeOut);
        } catch (InterruptedException | IOException e) {
            log.error("Failed to publish message due to " + e.getMessage());
            throw new NackException("The message is nacked due to " + e.getMessage(), e);
        } catch (TimeoutException e) {
            log.error("Failed to publish message due to " + e.getMessage());
            throw new TimeoutException("Timeout waiting for ACK " + e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("Failed to publish message due to " + e.getMessage());
            throw new IllegalArgumentException("DomainId limit exceeded " + e.getMessage(), e);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            if(!channel.isOpen()&& rabbitConnection.isOpen()){
                throw new RemRemPublishException("Channel was closed for Rabbitmq connection :: ",
                        factory, e);
            }
            throw new IOException("Failed to publish message due to " + e.getMessage(), e);
        }
    }

    /**
     * This method is used to give random channel
     * @return channel
     * @throws RemRemPublishException
     */
    private Channel giveMeRandomChannel() throws RemRemPublishException {
        if ((rabbitConnection == null || !rabbitConnection.isOpen())) {
            createRabbitMqConnection();
        }
        for (Channel channel : rabbitChannels) {
            if (channel.isOpen()) {
                return channel;
            }
        }
        try {
            Channel channel = createNewChannel();
            return channel;
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw new RemRemPublishException("Failed to create new channel for Rabbitmq :: ",
                    factory, e);
        }
    }

    /**
     * This method is used to get routing key type based on the eventType from the configuration file
     * 
     * @param eventType
     *            Eiffel eventType
     * @return type based on eventType if provided in the configuration file else null
     */
    public String getTypeRoutingKeyFromConfiguration(String eventType) {
        
        if (types != null) {
            String key = eventType + DOT + TYPE;
            try {
                String routingKey = types.getString(key);
                if (!routingKey.isBlank()) {
                    return routingKey;
                }else {
                    log.warn("Routing key from configuration is empty for :"+ key);
                }
            } catch (MissingResourceException e) {
		        log.warn("Routing key from configuration is null for :"+ key);
                return null;
            }
        }else {
            log.error("Uninitialized routing key configuration file ");
        }
        
		return null;
    }


}