/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.processors.azure;

import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.processors.azure.storage.utils.AzureBlobClientSideEncryptionMethod;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public abstract class AbstractAzureEncryptedBlobProcessor extends AbstractAzureBlobProcessor {
    public static final PropertyDescriptor CSE_KEY_TYPE = new PropertyDescriptor.Builder()
            .name("cse-key-type")
            .displayName("Client-Side Encryption key type")
            .required(true)
            .allowableValues(buildCseEncryptionMethodAllowableValues())
            .defaultValue(AzureBlobClientSideEncryptionMethod.NONE.name())
            .description("Specifies the key type to use for client-side encryption.")
            .build();

    public static final PropertyDescriptor CSE_SYMMETRIC_KEY_HEX = new PropertyDescriptor.Builder()
            .name("cse-symmetric-key-hex")
            .displayName("Symmetric Key (hexadecimal)")
            .description("When using symmetric client-side encryption, this is the raw key, encoded in hexadecimal")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(true)
            .build();

    private static AllowableValue[] buildCseEncryptionMethodAllowableValues() {
        final AzureBlobClientSideEncryptionMethod[] encryptionMethods = AzureBlobClientSideEncryptionMethod.values();
        List<AllowableValue> allowableValues = new ArrayList<>(encryptionMethods.length);
        for (AzureBlobClientSideEncryptionMethod em : encryptionMethods) {
            allowableValues.add(new AllowableValue(em.name(), em.name(), em.toString()));
        }

        return allowableValues.toArray(new AllowableValue[0]);
    }

    @Override
    public List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        List<PropertyDescriptor> properties = new ArrayList<>(super.getSupportedPropertyDescriptors());
        properties.add(CSE_KEY_TYPE);
        properties.add(CSE_SYMMETRIC_KEY_HEX);
        return properties;
    }

    @Override
    protected Collection<ValidationResult> customValidate(final ValidationContext context) {
        final List<ValidationResult> validationResults = new ArrayList<>(super.customValidate(context));

        final String cseKeyTypeValue = context.getProperty(CSE_KEY_TYPE).getValue();
        final AzureBlobClientSideEncryptionMethod cseKeyType = AzureBlobClientSideEncryptionMethod.valueOf(cseKeyTypeValue);

        final String cseSymmetricKeyHex = context.getProperty(CSE_SYMMETRIC_KEY_HEX).getValue();

        if (cseKeyType == AzureBlobClientSideEncryptionMethod.SYMMETRIC) {
            validationResults.addAll(validateSymmetricKey(cseSymmetricKeyHex));
        }

        return validationResults;
    }

    private List<ValidationResult> validateSymmetricKey(String keyHex) {
        List<ValidationResult> validationResults = new ArrayList<>();
        byte[] keyBytes = new byte[0];
        try {
            keyBytes = Hex.decodeHex(keyHex.toCharArray());
        } catch (DecoderException e) {
            validationResults.add(new ValidationResult.Builder().subject(CSE_SYMMETRIC_KEY_HEX.getName())
                    .explanation("Key must be valid hexadecimal string.").build());
        }

        if (keyBytes.length == 0) {
            validationResults.add(new ValidationResult.Builder().subject(CSE_SYMMETRIC_KEY_HEX.getName())
                    .explanation("Key must not be null.").build());
        } else {
            try {
                SymmetricKey key = new SymmetricKey("nifi", keyBytes);
            } catch (IllegalArgumentException e) {
                validationResults.add(new ValidationResult.Builder().subject(CSE_SYMMETRIC_KEY_HEX.getName())
                        .explanation(e.getMessage()).build());
            }
        }

        return validationResults;
    }

}
