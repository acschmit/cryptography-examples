/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.albertschmitt.cryptography.examples;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import org.albertschmitt.crypto.AESService;
import org.albertschmitt.crypto.RSAService;
import org.albertschmitt.crypto.common.DigestSHA;
import org.albertschmitt.crypto.common.RSAPrivateKey;
import org.albertschmitt.crypto.common.RSAPublicKey;

/**
 *
 * @author acschmit
 */
public class Example_040
{

	private static final String TESTDATA_DEC_FILE = "./Example_040.dec.txt";
	private static final String TESTDATA_ENC_FILE = "./Example_040.enc.txt";
	private static final String TESTDATA_FILE = "./Example_040.txt";

	private static final String publicKeyfile = "./Example_040_public_key.pem";
	private static final String keyFile = "./Example_040_keybytes.dat";

	public static void main(String[] args) throws Exception
	{
		System.out.println("Begin Example_040.");
		// Create some data to test with.
		testData();

		final RSAService rsa = new RSAService();
		File f = new File(publicKeyfile);
		if (!f.exists())
		{
			/**
			 * Create a public / private RSA key pair.
			 */
			System.out.println("Begin Create RSA Keys.");

			final ByteArrayOutputStream bos_private = new ByteArrayOutputStream();
			final FileOutputStream fos_public = new FileOutputStream(publicKeyfile);

			rsa.generateKey(bos_private, fos_public);
			InputStream bis_private = new ByteArrayInputStream(bos_private.toByteArray());

			bos_private.close();
			fos_public.close();

			System.out.println("End Create RSA Keys.");

			/**
			 * Generate an AES key then RSA encrypt it and write it to a file.
			 */
			System.out.println("Begin Create AES Key.");
			final AESService aes = new AESService();
			aes.generateKey();
			final byte[] key_bytes = aes.getAesKey();
			System.out.println("End Create AES Key.");

			System.out.println("Begin Encrypt AES Key.");
			final RSAPrivateKey privateKey = rsa.readPrivateKey(bis_private);
			final byte[] data = rsa.encode(key_bytes, privateKey);
			System.out.println("End Encrypt AES Key.");

			/**
			 * Write encrypted AES key to file.
			 */
			final Path path = Paths.get(keyFile);
			Files.write(path, data, StandardOpenOption.CREATE);
		}

		final Path path = Paths.get(keyFile);
		final byte[] data = Files.readAllBytes(path);

		final RSAPublicKey publicKey = rsa.readPublicKey(publicKeyfile);
		final byte[] key_bytes = rsa.decode(data, publicKey);

		final AESService aes = new AESService();
		aes.setAesKey(key_bytes);

		/**
		 * Use AES key to encrypt a file stream directly to another file stream.
		 */
		System.out.println("Begin Encrypt Data.");
		FileOutputStream outstream = new FileOutputStream(TESTDATA_ENC_FILE);
		FileInputStream instream = new FileInputStream(TESTDATA_FILE);
		aes.encode(instream, outstream);
		instream.close();
		outstream.close();
		System.out.println("End Encrypt Data.");

		/**
		 * Now decrypt the encrypted file using the same AES key.
		 */
		System.out.println("Begin Decrypt Data.");
		outstream = new FileOutputStream(TESTDATA_DEC_FILE);
		instream = new FileInputStream(TESTDATA_ENC_FILE);
		aes.decode(instream, outstream);
		instream.close();
		outstream.close();
		System.out.println("End Decrypt Data.");

		/**
		 * Now generate SHA256 hashes of the original and decrypted files. Their
		 * hash values should be the same.
		 */
		String shaOriginal = DigestSHA.sha256(new FileInputStream(TESTDATA_FILE));
		String shaDecripted = DigestSHA.sha256(new FileInputStream(TESTDATA_DEC_FILE));
		if (shaOriginal.compareTo(shaDecripted) == 0)
		{
			System.out.println("Encrypted and decrypted files are the same.");
		}
		else
		{
			System.out.println("Encrypted and decrypted files are NOT the same.");
		}
		System.out.println("End Example_040.");
	}

	private static void testData() throws IOException
	{
		if (!new File(TESTDATA_FILE).exists())
		{
			StringBuilder sb = new StringBuilder();
			sb.append("Lorem ipsum dolor sit amet, duo cu nobis epicurei hendrerit, mei agam elit an. Ea facer urbanitas his, voluptua luptatum corrumpit ea vis. An illum persecuti eos. Qui soluta vivendo et, quo meis vocent ex. Et vim vocent dissentiunt.\r\n");
			sb.append("Alia partem nam cu, at sed etiam ceteros sententiae, placerat perpetua scribentur ex per. Antiopam postulant assueverit ex eum, eu vim aeterno offendit molestiae, pri iisque pertinacia at. In vide platonem his, lucilius eleifend ad his. Duo ullum placerat ad, duo et civibus luptatum. Urbanitas reformidans at per, an solum civibus inciderint sed. Pro debet zril omnesque no, nisl adhuc summo sed ad.\r\n");
			sb.append("Sit paulo semper et, ad qui labore senserit definiebas, vidisse adipisci ad mei. Affert vivendo minimum vis eu. Per et aeque equidem, cu wisi incorrupte concludaturque quo. Ius ad stet reformidans.\r\n");
			sb.append("Mei at delenit efficiantur, ei dolorum vocibus facilisi mea, per ad erant quaeque copiosae. Mel in liber interpretaris, ex sed elit suscipiantur. Ad nisl animal aliquid eum. Integre senserit reformidans qui et, labores epicuri constituam at nam. Euismod consetetur id eam, doctus constituam his et, elit legere eu sed.\r\n");
			sb.append("In pro eirmod tibique indoctum, ex mel quaestio similique. Duo ad magna ancillae expetendis. Eos ut purto eirmod voluptua. At doming sententiae vis. Nibh percipit vel et, ne duo duis labitur aliquid.\r\n");
			sb.append("Adhuc zril pri ne, verear ullamcorper ut vim. Et tollit facilis quaestio mea, aeque probatus an vis, ex sed choro antiopam. Quis simul evertitur quo ad, an quo primis melius. Nisl tale mei id, ne wisi dissentiet voluptatibus mel, usu offendit indoctum ei. Est at nobis insolens posidonium.\r\n");
			sb.append("Et mel adhuc erroribus. Eos impetus urbanitas repudiandae ut, ne mea illum tollit pertinax, lorem quando at sit. Ex est option denique fabellas, habeo dolorum recteque id eam. Nam quodsi menandri et, te sit tamquam eruditi ornatus.\r\n");
			sb.append("Quo eius nihil electram ea, sea tota ipsum postulant id. Diam impedit veritus in pro, sea persius detracto conceptam ne, mei id enim solum dicit. Agam fugit epicurei at mea, eu eos decore aliquid. Homero essent timeam ex has, ius et quod quaeque. Ad vocent tamquam euripidis has, qui everti deleniti ad, stet modus detraxit ut sea.\r\n");
			sb.append("Novum melius mentitum sea ei, mea no affert deserunt urbanitas, vim tation ridens vocent at. Ad fugit propriae epicurei qui. Mea te reque porro. Per in delectus oporteat postulant.\r\n");
			sb.append("Sanctus intellegam pri in, per dicta maluisset ad. At eos aliquid accumsan, modus nulla tritani pro et. No duo partem sanctus accommodare, id his putent voluptua rationibus. Usu aliquid expetenda adolescens te. Quo sint dicat constituam et. Nec legendos sententiae ei, regione delectus sed at, sit homero appetere adversarium eu.\r\n");
			sb.append("Altera dolorum urbanitas nam ne, noluisse postulant mei et. Cibo dicam elaboraret vis te, cu vix hinc perfecto moderatius. Novum euismod sapientem at qui, molestie quaestio ex eam. Atqui possit vis no, sit ex inermis abhorreant. Maiorum vivendum te sed, enim nemore signiferumque mei ex, no postea diceret moderatius cum. Sed alia lorem scaevola ne, iuvaret accusamus consulatu nam id.\r\n");
			sb.append("Mel at veri errem sensibus, aliquid lucilius assueverit vim at. Mollis adversarium ei sed, eum an epicuri scaevola scripserit, paulo quodsi qui ad. At sit natum iriure singulis, pro quis verterem quaestio te. Commodo propriae definiebas cu nec. Vel at primis quodsi, per veniam bonorum scaevola ne.\r\n");
			sb.append("Te tibique scriptorem accommodare usu. Ad possim quaerendum mel. Id quidam explicari necessitatibus nam. Ex vide dolor omittam duo, quo vocent diceret verterem no. Usu diam copiosae oportere ea, in noluisse persecuti eos.\r\n");
			sb.append("Ut mei partem signiferumque, in sed euripidis reprehendunt, ex eum consetetur adipiscing. Mei at mollis virtute, ex mea saepe facilisis. Ferri inciderint eloquentiam vis te, eam congue maluisset no, nostro forensibus maiestatis cu mel. Ut quo tation platonem volutpat. Ei sed purto dolorum legendos, ea unum decore per.\r\n");
			sb.append("Eu eam erant deleniti, te qui quod nominati. Mel rebum homero ut, enim appareat nominati usu ex. Inani nulla percipitur est an. Eam at tempor pericula scriptorem. Ut vis vide latine.\r\n");
			sb.append("Ei eam congue exerci accommodare, facilisi consequuntur vix no. Ea solet graece pertinax vel, liber accommodare id pri, ex nostro perpetua laboramus vel. In brute sadipscing cum. Vel ei tale feugiat invenire. Ex est audire conclusionemque.\r\n");
			sb.append("Et maiorum efficiantur per. Has id maluisset patrioque omittantur, eu quem tollit assueverit vel. Eu nec utamur conceptam, has maiorum appetere instructior ad. Quo eu nisl noster copiosae.\r\n");
			sb.append("Scripta pertinax honestatis ne eum. Usu at erat everti phaedrum, at vis modo aperiri. Cetero vivendo quaerendum eam ad. Dico aliquando eu cum, putant inciderint vix eu.\r\n");
			sb.append("At vis lorem conceptam, ad pri vero dicat elaboraret, ad nobis imperdiet constituto duo. Bonorum tacimates et duo, mazim causae propriae sea ne. Mucius tibique argumentum mea eu. Eu usu detracto ocurreret. Id tation libris philosophia pri, vix id corpora democritum.\r\n");
			sb.append("Nam labores dignissim ut. An pro noluisse erroribus efficiendi, an has nisl malis philosophia. Autem electram democritum ad usu, per paulo propriae ea. Veri utamur in eos, summo debet decore ne \r\n");

			// Always use UTF-8 when converting to/from String and byte[].
			byte[] data = sb.toString().getBytes("UTF-8");
			Path path = Paths.get(TESTDATA_FILE);
			Files.write(path, data, StandardOpenOption.CREATE);
		}
	}
}
