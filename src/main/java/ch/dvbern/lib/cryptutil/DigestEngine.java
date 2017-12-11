package ch.dvbern.lib.cryptutil;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import ch.dvbern.lib.cryptutil.annotations.NonNull;
import ch.dvbern.lib.cryptutil.annotations.Nullable;

import static ch.dvbern.lib.cryptutil.Util.processFully;
import static java.util.Objects.requireNonNull;

public class DigestEngine {

	private static final int READ_BUFFER_SIZE = 4096;
	public static final String ALGO_SHA256 = "SHA-256";
	public static final String ALGO_SHA512 = "SHA-512";

	public boolean supportsSHA256(@Nullable Provider provider) {
		return supports(ALGO_SHA256, provider);
	}

	public @NonNull byte[] digestSHA256(@NonNull InputStream is, @Nullable Provider provider)
			throws IOException, DigestFailedException {
		return digestWithAlgo(is, ALGO_SHA256, provider);
	}

	public boolean supportsSHA512(@Nullable Provider provider) {
		return supports(ALGO_SHA512, provider);
	}

	public @NonNull byte[] digestSHA512(@NonNull InputStream is, @Nullable Provider provider)
			throws IOException, DigestFailedException {
		return digestWithAlgo(is, ALGO_SHA512, provider);
	}

	public boolean supports(@NonNull String algorithm, @Nullable Provider provider) {
		try {
			configureMessageDigest(algorithm, provider);
			return true;
		} catch (NoSuchAlgorithmException ignored) {
			return false;
		}
	}

	public @NonNull byte[] digestWithAlgo(
			@NonNull InputStream is,
			@NonNull String algorithm,
			@Nullable Provider provider
	) throws DigestFailedException, IOException {
		requireNonNull(is);
		requireNonNull(algorithm);

		MessageDigest md = null;
		try {
			md = configureMessageDigest(algorithm, provider);
		} catch (NoSuchAlgorithmException e) {
			throw new DigestFailedException("No such algorithm: " + algorithm, e);
		}
		byte[] digest = digestFully(md, is);

		return digest;
	}

	private @NonNull byte[] digestFully(@NonNull MessageDigest md, @NonNull InputStream is) throws IOException {
		requireNonNull(is);
		requireNonNull(md);

		processFully(is, READ_BUFFER_SIZE, md::update);

		return md.digest();
	}

	private @NonNull MessageDigest configureMessageDigest(@NonNull String algorithm, @Nullable Provider provider)
			throws NoSuchAlgorithmException {
		requireNonNull(algorithm);

		return provider != null
				? MessageDigest.getInstance(algorithm, provider)
				: MessageDigest.getInstance(algorithm);
	}

}