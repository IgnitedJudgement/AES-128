package hr.fer.kik;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * This class represents an abstract cipher.
 * 
 * @author Ivan Lokas
 */
public class Cipher {

	/**
	 * Constant used to initialize cipher to encryption mode.
	 */
	public static final int ENCRYPT_MODE = 0;
	/**
	 * Constant used to initialize cipher to decryption mode
	 * 
	 */
	public static final int DECRYPT_MODE = 1;

	/**
	 * List of supported modes of uses
	 */
	static List<Integer> supportedModeOfUses = Arrays.asList(ENCRYPT_MODE, DECRYPT_MODE);
	/**
	 * List of supported algorithms
	 */
	static List<String> supportedAlgorithms = Arrays.asList("AES128");
	/**
	 * List of supported modes of operations
	 */
	static List<String> supportedModesOfOperation = Arrays.asList(ModeOfOperation.values()).stream().map(e -> e.name())
			.toList();

	/**
	 * Map of algorithm names and their corresponding algorithm instances
	 */
	static Map<String, Algorithm> algorithmMap = new TreeMap<>() {
		/**
		 * Serial version UID for this object
		 */
		private static final long serialVersionUID = 1L;

		{
			put("AES128", new AES128());
		}
	};

	/**
	 * Map of the names of the mode of operation and their corresponding enum values
	 */
	static Map<String, ModeOfOperation> modesOfOperationMap = new TreeMap<>() {
		/**
		 * Serial version UID for this object
		 */
		private static final long serialVersionUID = 1L;

		{
			put("ECB", ModeOfOperation.ECB);
			put("CTR", ModeOfOperation.CTR);
		}
	};

	public Algorithm algorithm = null;
	public String modeOfOperation = null;
	public int modeOfUse = ENCRYPT_MODE;

	/**
	 * @return all supported modes of operation
	 */
	public static List<String> getSupportedModesOfOperation() {
		return supportedModesOfOperation;
	}

	/**
	 * @return all supported algorithms
	 */
	public static List<String> getSupportedAlgorithms() {
		return supportedAlgorithms;
	}

	/**
	 * @return current algorithm. Returns <code>null</code> if not initialized
	 */
	public Algorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * @return current mode of operation. Returns <code>null</code> if not
	 *         initialized
	 */
	public String getModeOfOperation() {
		return modeOfOperation;
	}

	/**
	 * @return current mode of use
	 */
	public int getModeOfUse() {
		return modeOfUse;
	}

	/**
	 * @param modeOfUse sets the current mode of use
	 */
	public void setModeOfUse(int modeOfUse) {
		this.modeOfUse = modeOfUse;
	}

	/**
	 * Method for initializing the cipher
	 * 
	 * @param transformation that will be initialized
	 */
	public void init(String transformation) {
		parseTransformation(transformation);
	}

	public int[][] doFinal(int[][] in, int[][] key) {
		if (!supportedModeOfUses.contains(modeOfUse)) {
			throw new IllegalArgumentException(
					String.format("Unexpected mode of use! Expected %d or %d, but recieved %d", ENCRYPT_MODE,
							DECRYPT_MODE, modeOfUse));
		}

		for (var entry : algorithmMap.entrySet()) {
			switch (entry.getKey()) {
			case "AES128" -> {
				((AES128) algorithm).setKey(key);
				((AES128) algorithm).setModeOfOperation(modesOfOperationMap.get(modeOfOperation));
			}
			}
		}

		return switch (modeOfUse) {
		case ENCRYPT_MODE -> algorithm.encrypt(in);
		case DECRYPT_MODE -> algorithm.decrypt(in);
		default -> throw new IllegalArgumentException();
		};

	}

	/**
	 * Helper methods that parses the given <code>transformation</code>
	 * 
	 * @param transformation that will be parsed
	 */
	private void parseTransformation(String transformation) {
		String[] elements = transformation.split("/");

		if (elements.length != 2) {
			throw new IllegalArgumentException(String.format(
					"Expected transformation string in format 'ALGORITHM/MODE_OF_OPERATION', but recieved '%s'!",
					transformation));
		}

		if (!supportedAlgorithms.contains(elements[0])) {
			throw new IllegalArgumentException(String.format("Unsupported algorithm! Expected '%s', but recieved '%s'!",
					supportedAlgorithms, elements[0].toUpperCase()));
		}

		algorithm = algorithmMap.get(elements[0]);

		if (!supportedModesOfOperation.contains(elements[1])) {
			throw new IllegalArgumentException(
					String.format("Unsupported mode of operation! Expected %s, but recieved '%s'!",
							supportedModesOfOperation.toString(), elements[1].toUpperCase()));
		}

		modeOfOperation = elements[1];
	}

}
