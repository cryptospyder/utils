import re
import regexes
import Paste

paste = Paste.Paste()
paste.text = [
"swagbarrera@gmail.com:Guantes0918.",
"woutermolemaker@hotmail.nl:olifant123",
"jesse269737@gmail.com:Breeze.9",
"randomguy14x@gmail.com:J5319414K",
"qqis_1@yahoo.com.hk:y53055172",
"neralla@msn.com:pa55word",
"krae7@bigpond.com:Amyemma1201",
"gustavoferrarimolon@gmail.com:gustavo12",
"Housingc@icloud.com:Hausfritz1",
"luke@tinsleycentral.us:qaz12",
"albert.osykin@icloud.com:AlbertDragon2003",
"luofusogames@hotmail.com:luofuso1010",
"kyler814@gmail.com:superman12",
"olaf.twh@gmail.com:ChuckNorris13"
]

print paste.match()
if paste.match():
	print paste.text

