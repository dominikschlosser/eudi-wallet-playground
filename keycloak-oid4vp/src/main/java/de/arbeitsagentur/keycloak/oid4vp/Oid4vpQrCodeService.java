/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.oid4vp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

/**
 * Service for generating QR codes for cross-device OID4VP flow.
 */
public class Oid4vpQrCodeService {

    private static final int DEFAULT_WIDTH = 200;
    private static final int DEFAULT_HEIGHT = 200;

    private final QRCodeWriter qrCodeWriter;

    public Oid4vpQrCodeService() {
        this.qrCodeWriter = new QRCodeWriter();
    }

    /**
     * Generate a QR code as a Base64-encoded PNG image.
     *
     * @param content The content to encode in the QR code
     * @return Base64-encoded PNG image string
     * @throws QrCodeGenerationException if QR code generation fails
     */
    public String generateQrCode(String content) {
        return generateQrCode(content, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    }

    /**
     * Generate a QR code as a Base64-encoded PNG image with specified dimensions.
     *
     * @param content The content to encode in the QR code
     * @param width Width of the QR code image in pixels
     * @param height Height of the QR code image in pixels
     * @return Base64-encoded PNG image string
     * @throws QrCodeGenerationException if QR code generation fails
     */
    public String generateQrCode(String content, int width, int height) {
        if (content == null || content.isBlank()) {
            throw new IllegalArgumentException("QR code content cannot be null or blank");
        }

        try {
            Map<EncodeHintType, Object> hints = Map.of(
                    EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M,
                    EncodeHintType.CHARACTER_SET, "UTF-8",
                    EncodeHintType.MARGIN, 1
            );

            BitMatrix bitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE, width, height, hints);

            // Convert BitMatrix to BufferedImage using standard Java (no JavaFX dependency)
            BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
            for (int x = 0; x < width; x++) {
                for (int y = 0; y < height; y++) {
                    image.setRGB(x, y, bitMatrix.get(x, y) ? 0x000000 : 0xFFFFFF);
                }
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ImageIO.write(image, "PNG", outputStream);

            return Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (WriterException e) {
            throw new QrCodeGenerationException("Failed to generate QR code: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new QrCodeGenerationException("Failed to write QR code image: " + e.getMessage(), e);
        }
    }

    /**
     * Exception thrown when QR code generation fails.
     */
    public static class QrCodeGenerationException extends RuntimeException {
        public QrCodeGenerationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
