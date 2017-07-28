package org.charter.nifi.processors;

import org.apache.nifi.processor.AbstractProcessor;

import java.nio.charset.StandardCharsets;
import java.security.Security;
//import java.text.Normalizer;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.annotation.behavior.EventDriven;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.annotation.behavior.SideEffectFree;
import org.apache.nifi.annotation.behavior.SupportsBatching;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processors.standard.EncryptContent.Encryptor;
//import org.apache.nifi.flowfile.attributes.CoreAttributes;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.StreamCallback;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.security.util.EncryptionMethod;
import org.apache.nifi.security.util.KeyDerivationFunction;
import org.apache.nifi.security.util.crypto.CipherUtility;
import org.apache.nifi.security.util.crypto.PasswordBasedEncryptor;
import org.apache.nifi.security.util.crypto.OpenPGPPasswordBasedEncryptor;
import org.apache.nifi.util.StopWatch;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

//import java.io.InputStream;
//import java.io.OutputStream;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
//import java.sql.Statement;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.nifi.dbcp.DBCPService;

@EventDriven
@SideEffectFree
@SupportsBatching
@InputRequirement(Requirement.INPUT_REQUIRED)
@Tags({"encryption", "decryption", "password", "Charter"})
@CapabilityDescription("Encrypts or decrypts a file with a unique private key, then stores the key encrypted into an external data store.")

public class IsilonEncryption extends AbstractProcessor {
    // Encryption
    private static final String ENCRYPT_MODE = "Encrypt";
    private static final String DECRYPT_MODE = "Decrypt";

    private static final String WEAK_CRYPTO_ALLOWED_NAME = "allowed";
    private static final String WEAK_CRYPTO_NOT_ALLOWED_NAME = "not-allowed";

    private static final PropertyDescriptor MODE = new PropertyDescriptor.Builder()
            .name("Mode")
            .description("Specifies whether the content should be encrypted or decrypted")
            .required(true)
            .allowableValues(ENCRYPT_MODE, DECRYPT_MODE)
            .defaultValue(ENCRYPT_MODE)
            .build();

    private static final PropertyDescriptor KEY_DERIVATION_FUNCTION = new PropertyDescriptor.Builder()
            .name("key-derivation-function")
            .displayName("Key Derivation Function")
            .description("Specifies the key derivation function to generate the key from the password (and salt)")
            .required(true)
            .allowableValues(buildKeyDerivationFunctionAllowableValues())
            .defaultValue(KeyDerivationFunction.BCRYPT.name())
            .build();

    private static final PropertyDescriptor ENCRYPTION_ALGORITHM = new PropertyDescriptor.Builder()
            .name("Encryption Algorithm")
            .description("The Encryption Algorithm to use")
            .required(true)
            .allowableValues(buildEncryptionMethodAllowableValues())
            .defaultValue(EncryptionMethod.MD5_128AES.name())
            .build();

    private static final PropertyDescriptor PASSWORD = new PropertyDescriptor.Builder()
            .name("Password")
            .description("The Password to use for encrypting or decrypting the data")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(true)
            .build();

    private static final PropertyDescriptor ALLOW_WEAK_CRYPTO = new PropertyDescriptor.Builder()
            .name("allow-weak-crypto")
            .displayName("Allow insecure cryptographic modes")
            .description("Overrides the default behavior to prevent unsafe combinations of encryption algorithms and short passwords on JVMs with limited strength cryptographic jurisdiction policies")
            .required(true)
            .allowableValues(buildWeakCryptoAllowableValues())
            .defaultValue(buildDefaultWeakCryptoAllowableValue().getValue())
            .build();

    private static final Relationship REL_SUCCESS = new Relationship.Builder().name("success")
            .description("Any FlowFile that is successfully encrypted or decrypted will be routed to success").build();

    private static final Relationship REL_FAILURE = new Relationship.Builder().name("failure")
            .description("Any FlowFile that cannot be encrypted or decrypted will be routed to failure").build();

    private List<PropertyDescriptor> properties;

    private Set<Relationship> relationships;

    static {
        // add BouncyCastle encryption providers
        Security.addProvider(new BouncyCastleProvider());
    }

    private static AllowableValue[] buildKeyDerivationFunctionAllowableValues() {
        final KeyDerivationFunction[] keyDerivationFunctions = KeyDerivationFunction.values();
        List<AllowableValue> allowableValues = new ArrayList<>(keyDerivationFunctions.length);
        for (KeyDerivationFunction kdf : keyDerivationFunctions) {
            allowableValues.add(new AllowableValue(kdf.name(), kdf.getName(), kdf.getDescription()));
        }

        return allowableValues.toArray(new AllowableValue[0]);
    }

    private static AllowableValue[] buildEncryptionMethodAllowableValues() {
        final EncryptionMethod[] encryptionMethods = EncryptionMethod.values();
        List<AllowableValue> allowableValues = new ArrayList<>(encryptionMethods.length);
        for (EncryptionMethod em : encryptionMethods) {
            allowableValues.add(new AllowableValue(em.name(), em.name(), em.toString()));
        }

        return allowableValues.toArray(new AllowableValue[0]);
    }

    private static AllowableValue[] buildWeakCryptoAllowableValues() {
        List<AllowableValue> allowableValues = new ArrayList<>();
        allowableValues.add(new AllowableValue(WEAK_CRYPTO_ALLOWED_NAME, "Allowed", "Operation will not be blocked and no alerts will be presented " +
                "when unsafe combinations of encryption algorithms and passwords are provided"));
        allowableValues.add(buildDefaultWeakCryptoAllowableValue());
        return allowableValues.toArray(new AllowableValue[0]);
    }

    private static AllowableValue buildDefaultWeakCryptoAllowableValue() {
        return new AllowableValue(WEAK_CRYPTO_NOT_ALLOWED_NAME, "Not Allowed", "When set, operation will be blocked and alerts will be presented to the user " +
                "if unsafe combinations of encryption algorithms and passwords are provided on a JVM with limited strength crypto. To fix this, see the Admin Guide.");
    }

    // SQL
    //public static final String RESULT_ROW_COUNT = "executesql.row.count";

    // Relationships

    private static final PropertyDescriptor DBCP_SERVICE = new PropertyDescriptor.Builder()
            .name("Database Connection Pooling Service")
            .description("The Controller Service that is used to obtain connection to database")
            .required(true)
            .identifiesControllerService(DBCPService.class)
            .build();

    private static final PropertyDescriptor SQL_SELECT_QUERY = new PropertyDescriptor.Builder()
            .name("SQL select query")
            .description("The SQL select query to execute. The query can be empty, a constant value, or built from attributes "
                    + "using Expression Language. If this property is specified, it will be used regardless of the content of "
                    + "incoming flowfiles. If this property is empty, the content of the incoming flow file is expected "
                    + "to contain a valid SQL select query, to be issued by the processor to the database. Note that Expression "
                    + "Language is not evaluated for flow file contents.")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(true)
            .build();

    private static final PropertyDescriptor SQL_INSERT_QUERY = new PropertyDescriptor.Builder()
            .name("SQL insert query")
            .description("The SQL insert query to execute. The query can be empty, a constant value, or built from attributes "
                    + "using Expression Language. If this property is specified, it will be used regardless of the content of "
                    + "incoming flowfiles. If this property is empty, the content of the incoming flow file is expected "
                    + "to contain a valid SQL select query, to be issued by the processor to the database. Note that Expression "
                    + "Language is not evaluated for flow file contents.")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(true)
            .build();

    private static final PropertyDescriptor FILE_PATH = new PropertyDescriptor.Builder()
            .name("File path")
            .description("This is the file path to use for saving the file, if applicable.")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(true)
            .build();

    private static final PropertyDescriptor FILE_NAME = new PropertyDescriptor.Builder()
            .name("File name")
            .description("This is the file name to use for saving and describing the file, if applicable.")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(true)
            .build();

    private static final PropertyDescriptor STORAGE_ID = new PropertyDescriptor.Builder()
            .name("Storage ID")
            .description("This is the unique ID number to store the attached item")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(true)
            .build();

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> properties = new ArrayList<>();
        properties.add(MODE);
        properties.add(KEY_DERIVATION_FUNCTION);
        properties.add(ENCRYPTION_ALGORITHM);
        properties.add(PASSWORD);
        properties.add(DBCP_SERVICE);
        properties.add(SQL_SELECT_QUERY);
        properties.add(SQL_INSERT_QUERY);
//        properties.add(QUERY_TIMEOUT);
        properties.add(STORAGE_ID);
        properties.add(FILE_PATH);
        properties.add(FILE_NAME);
        this.properties = Collections.unmodifiableList(properties);

        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return relationships;
    }

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return properties;
    }

    @Override
    protected Collection<ValidationResult> customValidate(final ValidationContext context) {
        final List<ValidationResult> validationResults = new ArrayList<>(super.customValidate(context));
        final String methodValue = context.getProperty(ENCRYPTION_ALGORITHM).getValue();
        final EncryptionMethod encryptionMethod = EncryptionMethod.valueOf(methodValue);
        final String password = context.getProperty(PASSWORD).getValue();
        final KeyDerivationFunction kdf = KeyDerivationFunction.valueOf(context.getProperty(KEY_DERIVATION_FUNCTION).getValue());

        boolean allowWeakCrypto = context.getProperty(ALLOW_WEAK_CRYPTO).getValue().equalsIgnoreCase(WEAK_CRYPTO_ALLOWED_NAME);
        validationResults.addAll(validatePBE(encryptionMethod, kdf, password, allowWeakCrypto));

        return validationResults;
    }

    private List<ValidationResult> validatePBE(EncryptionMethod encryptionMethod, KeyDerivationFunction kdf, String password, boolean allowWeakCrypto) {
        List<ValidationResult> validationResults = new ArrayList<>();
        boolean limitedStrengthCrypto = !PasswordBasedEncryptor.supportsUnlimitedStrength();

        // Password required (short circuits validation because other conditions depend on password presence)
        if (StringUtils.isEmpty(password)) {
            validationResults.add(new ValidationResult.Builder().subject(PASSWORD.getName())
                    .explanation(PASSWORD.getDisplayName() + " is required when using algorithm " + encryptionMethod.getAlgorithm()).build());
            return validationResults;
        }

        // If weak crypto is not explicitly allowed via override, check the password length and algorithm
        final int passwordBytesLength = password.getBytes(StandardCharsets.UTF_8).length;
        if (!allowWeakCrypto) {
            final int minimumSafePasswordLength = PasswordBasedEncryptor.getMinimumSafePasswordLength();
            if (passwordBytesLength < minimumSafePasswordLength) {
                validationResults.add(new ValidationResult.Builder().subject(PASSWORD.getName())
                        .explanation("Password length less than " + minimumSafePasswordLength + " characters is potentially unsafe. See Admin Guide.").build());
            }
        }

        // Multiple checks on machine with limited strength crypto
        if (limitedStrengthCrypto) {
            // Cannot use unlimited strength ciphers on machine that lacks policies
            if (encryptionMethod.isUnlimitedStrength()) {
                validationResults.add(new ValidationResult.Builder().subject(ENCRYPTION_ALGORITHM.getName())
                        .explanation(encryptionMethod.name() + " (" + encryptionMethod.getAlgorithm() + ") is not supported by this JVM due to lacking JCE Unlimited " +
                                "Strength Jurisdiction Policy files. See Admin Guide.").build());
            }

            // Check if the password exceeds the limit
            final boolean passwordLongerThanLimit = !CipherUtility.passwordLengthIsValidForAlgorithmOnLimitedStrengthCrypto(passwordBytesLength, encryptionMethod);
            if (passwordLongerThanLimit) {
                int maxPasswordLength = CipherUtility.getMaximumPasswordLengthForAlgorithmOnLimitedStrengthCrypto(encryptionMethod);
                validationResults.add(new ValidationResult.Builder().subject(PASSWORD.getName())
                        .explanation("Password length greater than " + maxPasswordLength + " characters is not supported by this JVM" +
                                " due to lacking JCE Unlimited Strength Jurisdiction Policy files. See Admin Guide.").build());
            }
        }

        // Check the KDF for compatibility with this algorithm
        List<String> kdfsForPBECipher = getKDFsForPBECipher(encryptionMethod);
        if (kdf == null || !kdfsForPBECipher.contains(kdf.name())) {
            final String displayName = KEY_DERIVATION_FUNCTION.getDisplayName();
            validationResults.add(new ValidationResult.Builder().subject(displayName)
                    .explanation(displayName + " is required to be " + StringUtils.join(kdfsForPBECipher,
                            ", ") + " when using algorithm " + encryptionMethod.getAlgorithm() + ". See Admin Guide.").build());
        }

        return validationResults;
    }

    private List<String> getKDFsForPBECipher(EncryptionMethod encryptionMethod) {
        List<String> kdfsForPBECipher = new ArrayList<>();
        for (KeyDerivationFunction k : KeyDerivationFunction.values()) {
            // Add all weak (legacy) KDFs except NONE
            if (!k.isStrongKDF() && !k.equals(KeyDerivationFunction.NONE)) {
                kdfsForPBECipher.add(k.name());
                // If this algorithm supports strong KDFs, add them as well
            } else if ((encryptionMethod.isCompatibleWithStrongKDFs() && k.isStrongKDF())) {
                kdfsForPBECipher.add(k.name());
            }
        }
        return kdfsForPBECipher;
    }

    private String getFileKey(final String storageID, final String masterKey, final DBCPService dbcpService) {
       final String selectQuery =
           "select aes_decrypt(encryptionkey,unhex(sha2(?,512))) from Isilon.EncryptionKeys where storageID = ?";
        final String fileKey;
        try (
                final Connection con = dbcpService.getConnection();
                final PreparedStatement st = con.prepareStatement(selectQuery);
            )
        {
            st.setString(1, masterKey);
            st.setString(2, storageID);
            if (st.execute()) {
                final ResultSet rs = st.getResultSet();
                rs.next();
                fileKey = rs.getString(1);
            } else {
                throw new ProcessException("Failed to retrieve file key");
            }
        } catch (final SQLException e) {
            throw new ProcessException(e);
        }
        return fileKey;
    }

    private String setFileKey(final String storageID, final String masterKey, final String filePath,
                              final String fileName, final DBCPService dbcpService) {

        final String insertQuery =
             "insert into Isilon.EncryptionKeys (storageID, path, filename, encryptionkey) "
            +"values ( ?, ?, ?, aes_encrypt(?, unhex(sha2(?,512) )));";
        final String fileKey = UUID.randomUUID().toString();
        try (
                final Connection con = dbcpService.getConnection();
                final PreparedStatement st = con.prepareStatement(insertQuery)
            )
        {

            st.setString(1, storageID);
            st.setString(2, filePath);
            st.setString(3, fileName);
            st.setString(4, fileKey);
            st.setString(5, masterKey);

            if (st.executeUpdate() == 1) {
                return fileKey;
            } else {
                throw new ProcessException("Failed to update DB");
            }
        } catch (final SQLException e) {
            throw new ProcessException(e);
        }
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }

//        final char[] passphrase = Normalizer.normalize(password, Normalizer.Form.NFC).toCharArray();
        final String method = context.getProperty(ENCRYPTION_ALGORITHM).getValue();
        final EncryptionMethod encryptionMethod = EncryptionMethod.valueOf(method);
        final KeyDerivationFunction kdf = KeyDerivationFunction.valueOf(context.getProperty(KEY_DERIVATION_FUNCTION).getValue());
        final boolean encrypt = context.getProperty(MODE).getValue().equalsIgnoreCase(ENCRYPT_MODE);

        String fileKey = context.getProperty(STORAGE_ID).toString();

        Encryptor encryptor;
        StreamCallback callback;

        final String fileKeyPassword    = context.getProperty(PASSWORD).evaluateAttributeExpressions(flowFile).toString();
        final String filePath           = context.getProperty(FILE_PATH).evaluateAttributeExpressions(flowFile).toString();
        final String fileName           = context.getProperty(FILE_NAME).evaluateAttributeExpressions(flowFile).toString();
        String storageID                = context.getProperty(STORAGE_ID).evaluateAttributeExpressions(flowFile).toString();

        session.putAttribute(flowFile,"isilon.storageID",storageID);
        session.putAttribute(flowFile,"isilon.filePath",filePath);
        session.putAttribute(flowFile,"isilon.fileName",fileName);

        // SQL
        final DBCPService dbcpService = context.getProperty(DBCP_SERVICE).asControllerService(DBCPService.class);
        final String selectQuery =
                "select aes_decrypt(encryptionkey,unhex(sha2(?,512))) from Isilon.EncryptionKeys where storageID = ?";
        final String insertQuery =
                 "insert into Isilon.EncryptionKeys (storageID, path, filename, encryptionkey) "
                +"values ( ?, ?, ?, aes_encrypt(?, unhex(sha2(?,512) )));";
        // Shared
        final ComponentLog logger = getLogger();

        try {
            if (encrypt) {
                try {
                    final String testKey = setFileKey(storageID, fileKeyPassword, filePath, fileName, dbcpService);
                    encryptor = (Encryptor) new PasswordBasedEncryptor(encryptionMethod, testKey.toCharArray(), kdf);
                    callback = encryptor.getEncryptionCallback();
                }
                catch (final SQLException e) {
                    logger.error("failed to update DB - ",e);
                    session.transfer(flowFile, REL_FAILURE);
                    throw new ProcessException(e);
                }
            } else { // decrypt
                final String testKey = getFileKey(storageID, fileKeyPassword, dbcpService);
                try (
                    final Connection con = dbcpService.getConnection();
                    final PreparedStatement st = con.prepareStatement(selectQuery)
                ) {
                    st.setString(1, fileKeyPassword);
                    st.setString(2, storageID);
                    if (st.execute()) {
                        final ResultSet rs = st.getResultSet();
                        rs.next();
                        fileKey = rs.getString(1);

                        encryptor = new PasswordBasedEncryptor(encryptionMethod, fileKey.toCharArray(), kdf);
                        callback = encryptor.getDecryptionCallback();
                    } else {
                        throw new ProcessException("Failed to retrieve file key");
                    }
                } catch (final SQLException e) {
                    throw new ProcessException(e);
                }
            }

        } catch (final Exception e) {

            logger.error("Failed to initialize {}cryption algorithm because - ", new Object[]{encrypt ? "en" : "de", e});
            session.putAttribute(flowFile,"isilon.error",e.getMessage());

            session.transfer(flowFile, REL_FAILURE);
//            context.yield();
            return;
        }

        try {
            final StopWatch stopWatch = new StopWatch(true);
            flowFile = session.write(flowFile, callback);
            // TODO: DoKeyRetrieval();
            logger.info("successfully {}crypted {}", new Object[]{encrypt ? "en" : "de", flowFile});
            session.getProvenanceReporter().modifyContent(flowFile, stopWatch.getElapsed(TimeUnit.MILLISECONDS));
            session.transfer(flowFile, REL_SUCCESS);
        } catch (final ProcessException e) {
            logger.error("Cannot {}crypt {} - ", new Object[]{encrypt ? "en" : "de", flowFile, e});
            session.transfer(flowFile, REL_FAILURE);
        }
    }
}