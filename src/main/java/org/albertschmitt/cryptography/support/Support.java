/**
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Albert C Schmitt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.albertschmitt.cryptography.support;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * Various methods to support the example classes.
 */
public class Support
{

	/**
	 * Create a data file for testing.
	 *
	 * @param filename The name of the file to create.
	 * @throws IOException
	 */
	public static void testData(String filename) throws IOException
	{
		if (!new File(filename).exists())
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
			Path path = Paths.get(filename);
			Files.write(path, data, StandardOpenOption.CREATE);
		}
	}
}
