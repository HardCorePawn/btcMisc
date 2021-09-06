#
# Copyright (c) 2013 Pavol Rusnak
# Copyright (c) 2017 mruddy
# Copyright (c) 2021 HCP
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import binascii
import bisect
import ed25519
import hashlib
import hmac
import itertools
import os
import struct
import sys
import unicodedata
from base58 import b58encode
from datetime import datetime

from pbkdf2 import PBKDF2

PBKDF2_ROUNDS = 2048
privdev = 0x80000000

#motor reopen nice infant eternal shock foil duck early extra license toddler burden cram carpet west sorry scatter
#talk wrong soccer file strike radio cheap blush worth torch scan retreat pyramid soldier swim census receive impact ripple flee accuse undo year exotic
#seedStruct = [{'word':'talk'},
#  {'word':'wrong'},
#  {'word':'soccer'},
#  {'word':'file'},
#  {'word':'strike'},
#  {'word':'cheap'},
#  {'word':'blush'},
#  {'word':'worth'},
#  {'word':'torch'},
#  {'word':'scan'},
#  {'word':'retreat'},
#  {'word':'pyramid'},
#  {'word':'soldier'},
#  {'word':'swim'},
#  {'word':'census'},
#  {'word':'receive'},
#  {'word':'impact'},
#  {'word':'ripple'},
#  {'word':'flee'},
#  {'word':'accuse'},
#  {'word':'undo'},
#  {'word':'year'},
#  {'word':'exotic'},
#  ]

seedStruct = []

words = [[],[],[],
['act','add','age','aim','air','all','any','arm','art','ask','bag',
'bar','bid','box','boy','bus','can','car','cat','cry','cup','dad',
'day','dog','dry','egg','end','era','eye','fan','fat','fee','few',
'fit','fix','fly','fog','fox','fun','gap','gas','gun','hat',
'hen','hip','hub','ice','ill','jar','job','joy','key','kid','kit',
'lab','law','leg','mad','man','mix','mom','net','now','nut','oak',
'off','oil','old','one','own','pen','pet','pig','put','raw','rib',
'rug','run','sad','say','sea','shy','six','ski','spy','sun','tag',
'ten','tip','toe','top','toy','try','two','use','van','way','web',
'wet','win','you','zoo'],
['able','acid','also','arch','area','army','atom','aunt','auto','away','axis',
'baby','ball','base','bean','beef','belt','best','bike','bind','bird','blue',
'blur','boat','body','boil','bomb','bone','book','boss','bulb','bulk','busy',
'buzz','cage','cake','call','calm','camp','card','cart','case','cash','cave',
'chat','chef','city','clap','claw','clay','clip','clog','club','code','coil',
'coin','come','cook','cool','copy','core','corn','cost','cram','crew','crop',
'cube','cute','damp','dash','dawn','deal','deer','defy','deny','desk','dial',
'dice','diet','dirt','dish','doll','door','dose','dove','draw','drip','drop',
'drum','duck','dumb','dune','dust','duty','earn','east','easy','echo','edge',
'edit','else','evil','exit','face','fade','fall','fame','farm','feed','feel',
'file','film','find','fine','fire','fish','flag','flat','flee','flip',
'foam','foil','fold','food','foot','fork','frog','fuel','fury','gain','game',
'gasp','gate','gaze','gift','girl','give','glad','glow','glue','goat','gold',
'good','gown','grab','grid','grit','grow','hair','half','hand','hard','have',
'hawk','head','help','hero','high','hill','hint','hire','hold','hole','home',
'hood','hope','horn','host','hour','huge','hunt','hurt','icon','idea','idle',
'inch','into','iron','item','jazz','join','joke','jump','junk','just','keen',
'keep','kick','kind','kiss','kite','kiwi','knee','know','lady','lake','lamp',
'lava','lawn','lazy','leaf','left','lend','lens','liar','life','lift','like',
'limb','link','lion','list','live','load','loan','lock','long','loop','loud',
'love','maid','mail','main','make','mask','mass','math','maze','mean','meat',
'melt','menu','mesh','milk','mind','miss','moon','more','move','much','mule',
'must','myth','name','near','neck','need','nest','news','next','nice','nose',
'note','obey','odor','okay','omit','once','only','open','oval','oven','over',
'pact','page','pair','palm','park','pass','path','pave','pear','pill','pink',
'pipe','play','plug','poem','poet','pole','pond','pony','pool','post','pull',
'pulp','push','quit','quiz','race','rack','rail','rain','ramp','rare','rate',
'real','rely','rent','rice','rich','ride','ring','riot','risk','road',
'room','rose','rude','rule','safe','sail','salt','same','sand','save','scan',
'seat','seed','seek','sell','shed','ship','shoe','shop','sick','side','sign',
'silk','sing','size','skin','slab','slam','slim','slot','slow','snap','snow',
'soap','sock','soda','soft','song','soon','sort','soul','soup','spin','spot',
'stay','stem','step','such','suit','sure','swap','swim','tail','talk','tank',
'tape','task','taxi','team','tell','tent','term','test','text','that','then',
'they','this','tide','tilt','time','tiny','tone','tool','toss','town','trap',
'tray','tree','trim','trip','true','tube','tuna','turn','twin','type','ugly',
'undo','unit','upon','urge','used','vast','verb','very','view','visa','void',
'vote','wage','wait','walk','wall','want','warm','wash','wasp','wave','wear',
'west','what','when','whip','wide','wife','wild','will','wine','wing','wink',
'wire','wise','wish','wolf','wood','wool','word','work','wrap','yard','year',
'zero','zone'],
['about','above','abuse','actor','adapt','admit','adult','again','agent','agree','ahead',
'aisle','alarm','album','alert','alien','alley','allow','alone','alpha','alter','among',
'anger','angle','angry','ankle','apart','apple','april','arena','argue','armed','armor',
'arrow','asset','audit','avoid','awake','aware','awful','bacon','badge','basic','beach',
'begin','below','bench','birth','black','blade','blame','blast','bleak','bless','blind',
'blood','blush','board','bonus','boost','brain','brand','brass','brave','bread','brick',
'brief','bring','brisk','broom','brown','brush','buddy','build','burst','buyer','cabin',
'cable','canal','candy','canoe','cargo','carry','catch','cause','chair','chalk','chaos',
'chase','cheap','check','chest','chief','child','chunk','cigar','civil','claim',
'clean','clerk','click','cliff','climb','clock','close','cloth','cloud','clown','clump',
'coach','coast','color','comic','coral','couch','cover','crack','craft','crane','crash',
'crawl','crazy','cream','creek','crime','crisp','cross','crowd','cruel','crush','curve',
'cycle','dance','delay','depth','diary','dizzy','donor','draft','drama','dream','dress',
'drift','drill','drink','drive','dutch','dwarf','eager','eagle','early','earth','eight',
'elbow','elder','elite','empty','enact','enemy','enjoy','enter','entry','equal','equip',
'erase','erode','error','erupt','essay','evoke','exact','exile','exist','extra','faint',
'faith','false','fancy','fatal','fault','fence','fetch','fever','fiber','field','final',
'first','flame','flash','float','flock','floor','fluid','flush','focus','force','forum',
'found','frame','fresh','front','frost','frown','fruit','funny','gauge','genre','ghost',
'giant','glare','glass','glide','globe','gloom','glory','glove','goose','grace','grain',
'grant','grape','grass','great','green','grief','group','grunt','guard','guess','guide',
'guilt','habit','happy','harsh','heart','heavy','hello','hobby','honey','horse','hotel',
'hover','human','humor','hurry','image','index','inner','input','issue','ivory','jeans',
'jelly','jewel','judge','juice','knife','knock','label','labor','large','later','latin',
'laugh','layer','learn','leave','legal','lemon','level','light','limit','local','logic',
'loyal','lucky','lunar','lunch','magic','major','mango','maple','march','match','medal',
'media','mercy','merge','merit','merry','metal','mimic','minor','mixed','model','month',
'moral','motor','mouse','movie','music','naive','nasty','nerve','never','night','noble',
'noise','north','novel','nurse','occur','ocean','offer','often','olive','onion','opera',
'orbit','order','organ','other','outer','owner','ozone','panda','panel','panic','paper',
'party','patch','pause','peace','phone','photo','piano','piece','pilot','pitch','pizza',
'place','plate','pluck','point','polar','power','price','pride','print','prize','proof',
'proud','pulse','punch','pupil','puppy','purse','quick','quote','radar','radio','raise',
'rally','ranch','range','rapid','raven','razor','ready','relax','renew','ridge',
'rifle','right','rigid','rival','river','roast','robot','rough','round','route','royal',
'rural','salad','salon','sauce','scale','scare','scene','scout','scrap','scrub','sense',
'setup','seven','shaft','share','shell','shift','shine','shock','shoot','short','shove',
'shrug','siege','sight','silly','since','siren','skate','skill','skirt','skull','sleep',
'slice','slide','slush','small','smart','smile','smoke','snack','snake','sniff','solar',
'solid','solve','sorry','south','space','spare','spawn','speak','speed','spell',
'spend','spice','spike','split','spoil','spoon','sport','spray','staff','stage','stamp',
'stand','start','state','steak','steel','stick','still','sting','stock','stone','stool',
'story','stove','stuff','style','sugar','sunny','super','surge','swamp','swarm','swear',
'sweet','swift','swing','sword','syrup','table','taste','teach','thank','theme','there',
'thing','three','throw','thumb','tiger','tired','title','toast','today','token','tooth',
'topic','torch','total','tower','track','trade','trash','treat','trend','trial',
'tribe','trick','truck','truly','trust','truth','twice','twist','uncle','under','until',
'upper','upset','urban','usage','usual','vague','valid','valve','vapor','vault','venue',
'video','virus','visit','vital','vivid','vocal','voice','wagon','waste','water','weird',
'whale','wheat','wheel','where','width','woman','world','worry','worth','wreck','wrist',
'write','wrong','young','youth','zebra'],
['absent','absorb','absurd','access','accuse','across','action','actual','addict','adjust','advice',
'affair','afford','afraid','almost','always','amount','amused','anchor','animal','annual','answer',
'appear','arctic','around','arrest','arrive','artist','aspect','assist','assume','asthma','attack',
'attend','august','author','autumn','bamboo','banana','banner','barely','barrel','basket','battle',
'beauty','become','before','behave','behind','betray','better','beyond','bitter','blouse','border',
'boring','borrow','bottom','bounce','breeze','bridge','bright','broken','bronze','bubble','budget',
'bullet','bundle','bunker','burden','burger','butter','cactus','camera','cancel','cannon','canvas',
'carbon','carpet','casino','castle','casual','cattle','caught','celery','cement','census',
'cereal','change','charge','cheese','cherry','choice','choose','circle','clever','client','clinic',
'clutch','coffee','column','common','copper','cotton','couple','course','cousin','coyote','cradle',
'crater','credit','critic','crouch','cruise','crunch','custom','damage','danger','daring','debate',
'debris','decade','decide','define','degree','demand','demise','denial','depart','depend','deputy',
'derive','desert','design','detail','detect','device','devote','diesel','differ','dinner','direct',
'divert','doctor','domain','donate','donkey','double','dragon','during','easily','effort',
'either','embark','embody','emerge','employ','enable','energy','engage','engine','enlist','enough',
'enrich','enroll','ensure','entire','escape','estate','ethics','evolve','excess','excite','excuse',
'exotic','expand','expect','expire','expose','extend','fabric','family','famous','father','female',
'figure','filter','finger','finish','fiscal','flavor','flight','flower','follow','forest','forget',
'fossil','foster','friend','fringe','frozen','future','gadget','galaxy','garage','garden','garlic',
'gather','genius','gentle','giggle','ginger','glance','gospel','gossip','govern','guitar','hammer',
'harbor','hazard','health','height','helmet','hidden','hockey','hollow','horror','humble','hungry',
'hurdle','hybrid','ignore','immune','impact','impose','income','indoor','infant','inform','inhale',
'inject','injury','inmate','insane','insect','inside','intact','invest','invite','island','jacket',
'jaguar','jungle','junior','kidney','kitten','ladder','laptop','leader','legend','length','lesson',
'letter','liquid','little','lizard','lonely','lounge','lumber','luxury','lyrics','magnet','mammal',
'manage','manual','marble','margin','marine','market','master','matrix','matter','meadow','melody',
'member','memory','method','middle','minute','mirror','misery','mobile','modify','moment','monkey',
'mother','motion','muffin','muscle','museum','mutual','myself','napkin','narrow','nation','nature',
'nephew','noodle','normal','notice','number','object','oblige','obtain','office','online','oppose',
'option','orange','orient','orphan','output','oxygen','oyster','paddle','palace','parade','parent',
'parrot','patrol','peanut','pencil','people','pepper','permit','person','phrase','picnic','pigeon',
'pistol','planet','please','pledge','plunge','police','potato','powder','praise','prefer','pretty',
'prison','profit','public','purity','puzzle','rabbit','random','rather','reason','recall','recipe',
'record','reduce','reform','refuse','region','regret','reject','relief','remain','remind','remove',
'render','reopen','repair','repeat','report','rescue','resist','result','retire','return','reveal',
'review','reward','rhythm','ribbon','ripple','ritual','robust','rocket','rookie','rotate','rubber',
'runway','saddle','salmon','salute','sample','scheme','school','screen','script','search','season',
'second','secret','select','senior','series','settle','shadow','shield','shiver','shrimp','silent',
'silver','simple','sister','sketch','slight','slogan','smooth','soccer','social','source','sphere',
'spider','spirit','spread','spring','square','stable','stairs','stereo','street','strike','strong',
'submit','subway','sudden','suffer','summer','sunset','supply','survey','switch','symbol','system',
'tackle','talent','target','tattoo','tenant','tennis','theory','thrive','ticket','timber','tissue',
'toilet','tomato','tongue','topple','toward','tragic','travel','trophy','tumble','tunnel','turkey',
'turtle','twelve','twenty','unable','unfair','unfold','unique','unlock','unveil','update','uphold',
'useful','vacant','vacuum','valley','vanish','velvet','vendor','verify','vessel','viable','violin',
'visual','volume','voyage','walnut','wealth','weapon','weasel','window','winner','winter','wisdom',
'wonder','yellow'],
['abandon','ability','account','achieve','acquire','actress','address','advance','aerobic','airport','alcohol',
'already','amateur','amazing','analyst','ancient','another','antenna','antique','anxiety','apology','approve',
'arrange','artwork','assault','athlete','attract','auction','average','avocado','awesome','awkward','balance',
'balcony','bargain','because','believe','benefit','between','bicycle','biology','blanket','blossom','bracket',
'brother','buffalo','cabbage','capable','capital','captain','catalog','caution','ceiling','century','certain',
'chapter','chicken','chimney','chronic','chuckle','citizen','clarify','cluster','coconut','collect','combine',
'comfort','company','concert','confirm','connect','control','correct','country','cricket','crucial',
'crumble','crystal','culture','curious','current','curtain','cushion','decline','defense','deliver','dentist',
'deposit','despair','destroy','develop','diagram','diamond','digital','dignity','dilemma','disease','dismiss',
'display','divorce','dolphin','drastic','dynamic','ecology','economy','educate','element','embrace',
'emotion','empower','endless','endorse','enforce','enhance','episode','erosion','essence','eternal','example',
'exclude','execute','exhaust','exhibit','explain','eyebrow','faculty','fantasy','fashion','fatigue',
'feature','federal','fiction','fitness','fortune','forward','fragile','furnace','gallery','garbage','garment',
'general','genuine','gesture','giraffe','glimpse','goddess','gorilla','gravity','grocery','hamster','harvest',
'history','holiday','hundred','husband','illegal','illness','imitate','immense','improve','impulse','include',
'inflict','inherit','initial','inquiry','inspire','install','involve','isolate','jealous','journey','ketchup',
'kingdom','kitchen','laundry','lawsuit','lecture','leisure','leopard','liberty','library','license','lobster',
'lottery','luggage','machine','mandate','mansion','maximum','measure','mention','message','million','minimum',
'miracle','mistake','mixture','monitor','monster','morning','mystery','neglect','neither','network','neutral',
'nominee','notable','nothing','nuclear','obscure','observe','obvious','october','olympic','opinion','orchard',
'ostrich','outdoor','outside','panther','patient','pattern','payment','peasant','pelican','penalty','perfect',
'picture','pioneer','plastic','popular','portion','pottery','poverty','predict','prepare','present','prevent',
'primary','private','problem','process','produce','program','project','promote','prosper','protect','provide',
'pudding','pumpkin','purpose','pyramid','quality','quantum','quarter','raccoon','rebuild','receive','recycle',
'reflect','regular','release','replace','require','retreat','reunion','romance','sadness','satisfy','satoshi',
'sausage','scatter','science','section','segment','seminar','service','session','shallow','sheriff','shuffle',
'sibling','similar','situate','slender','soldier','someone','spatial','special','sponsor','squeeze','stadium',
'stomach','student','stumble','subject','success','suggest','supreme','surface','suspect','sustain','swallow',
'symptom','thought','thunder','tobacco','toddler','tonight','tornado','tourist','traffic','trigger','trouble',
'trumpet','tuition','typical','unaware','uncover','unhappy','uniform','unknown','unusual','upgrade','useless',
'utility','various','vehicle','venture','version','veteran','vibrant','vicious','victory','village','vintage',
'virtual','volcano','warfare','warrior','weather','wedding','weekend','welcome','whisper','witness','wrestle'],
['abstract','accident','acoustic','announce','artefact','attitude','bachelor','broccoli','business','category','champion',
'cinnamon','congress','consider','convince','cupboard','daughter','december','decorate','decrease','describe','dinosaur',
'disagree','discover','disorder','distance','document','electric','elephant','elevator','envelope','evidence','exchange',
'exercise','favorite','february','festival','frequent','hedgehog','hospital','identify','increase','indicate','industry',
'innocent','interest','kangaroo','language','marriage','material','mechanic','midnight','mosquito','mountain','multiply',
'mushroom','negative','ordinary','original','physical','position','possible','practice','priority','property','purchase',
'question','remember','resemble','resource','response','scissors','scorpion','security','sentence','shoulder','solution',
'squirrel','strategy','struggle','surprise','surround','together','tomorrow','tortoise','transfer','umbrella','universe']]

class ConfigurationError(Exception):
    pass

# From <http://tinyurl.com/p54ocsk>
def binary_search(a, x, lo=0, hi=None):   # can't use a to specify default for hi
    hi = hi if hi is not None else len(a) # hi defaults to len(a)
    pos = bisect.bisect_left(a, x, lo, hi)   # find insertion position
    return (pos if pos != hi and a[pos] == x else -1) # don't walk off the end

class Mnemonic(object):
    def __init__(self, language):
        self.radix = 2048
        with open('%s/%s.txt' % (self._get_directory(), language), 'r') as f:
            self.wordlist = [w.strip() for w in f.readlines()]
        if len(self.wordlist) != self.radix:
            raise ConfigurationError('Wordlist should contain %d words, but it contains %d words.' % (self.radix, len(self.wordlist)))

    @classmethod
    def _get_directory(cls):
        return os.path.join(os.path.dirname(__file__), 'wordlist')

    @classmethod
    def list_languages(cls):
        return [f.split('.')[0] for f in os.listdir(cls._get_directory()) if f.endswith('.txt')]

    @classmethod
    def normalize_string(cls, txt):
        if isinstance(txt, str if sys.version < '3' else bytes):
            utxt = txt.decode('utf8')
        elif isinstance(txt, unicode if sys.version < '3' else str):
            utxt = txt
        else:
            raise TypeError("String value expected")

        return unicodedata.normalize('NFKD', utxt)

    @classmethod
    def detect_language(cls, code):
        first = code.split(' ')[0]
        languages = cls.list_languages()

        for lang in languages:
            mnemo = cls(lang)
            if first in mnemo.wordlist:
                return lang

        raise ConfigurationError("Language not detected")

    def generate(self, strength=128):
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError('Strength should be one of the following [128, 160, 192, 224, 256], but it is not (%d).' % strength)
        return self.to_mnemonic(os.urandom(strength // 8))

    # Adapted from <http://tinyurl.com/oxmn476>
    def to_entropy(self, words):
        if not isinstance(words, list):
            words = words.split(' ')
        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError('Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not (%d).' % len(words))
        # Look up all the words in the list and construct the
        # concatenation of the original entropy and the checksum.
        concatLenBits = len(words) * 11
        concatBits = [False] * concatLenBits
        wordindex = 0
        for word in words:
            # Find the words index in the wordlist
            ndx = binary_search(self.wordlist, word)
            if ndx < 0:
                raise LookupError('Unable to find "%s" in word list.' % word)
            # Set the next 11 bits to the value of the index.
            for ii in range(11):
                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0
            wordindex += 1
        checksumLengthBits = concatLenBits // 33
        entropyLengthBits = concatLenBits - checksumLengthBits
        # Extract original entropy as bytes.
        entropy = bytearray(entropyLengthBits // 8)
        for ii in range(len(entropy)):
            for jj in range(8):
                if concatBits[(ii * 8) + jj]:
                    entropy[ii] |= 1 << (7 - jj)
        # Take the digest of the entropy.
        hashBytes = hashlib.sha256(entropy).digest()
        if sys.version < '3':
            hashBits = list(itertools.chain.from_iterable(([ord(c) & (1 << (7 - i)) != 0 for i in range(8)] for c in hashBytes)))
        else:
            hashBits = list(itertools.chain.from_iterable(([c & (1 << (7 - i)) != 0 for i in range(8)] for c in hashBytes)))
        # Check all the checksum bits.
        for i in range(checksumLengthBits):
            if concatBits[entropyLengthBits + i] != hashBits[i]:
                raise ValueError('Failed checksum.')
        return entropy

    def to_mnemonic(self, data):
        if len(data) not in [16, 20, 24, 28, 32]:
            raise ValueError('Data length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d).' % len(data))
        h = hashlib.sha256(data).hexdigest()
        b = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8) + \
            bin(int(h, 16))[2:].zfill(256)[:len(data) * 8 // 32]
        result = []
        for i in range(len(b) // 11):
            idx = int(b[i * 11:(i + 1) * 11], 2)
            result.append(self.wordlist[idx])
        if self.detect_language(' '.join(result)) == 'japanese': # Japanese must be joined by ideographic space.
            result_phrase = u'\xe3\x80\x80'.join(result)
        else:
            result_phrase = ' '.join(result)
        return result_phrase

    def check(self, mnemonic):
        if self.detect_language(mnemonic.replace(u'\xe3\x80\x80', ' ')) == 'japanese':
            mnemonic = mnemonic.replace(u'\xe3\x80\x80', ' ') # Japanese will likely input with ideographic space.
        mnemonic = mnemonic.split(' ')
        if len(mnemonic) % 3 > 0:
            return False
        try:
            idx = map(lambda x: bin(self.wordlist.index(x))[2:].zfill(11), mnemonic)
            b = ''.join(idx)
        except:
            return False
        l = len(b)
        d = b[:l // 33 * 32]
        h = b[-l // 33:]
        nd = binascii.unhexlify(hex(int(d, 2))[2:].rstrip('L').zfill(l // 33 * 8))
        nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[:l // 33]
        return h == nh

    def expand_word(self, prefix):
        if prefix in self.wordlist:
            return prefix
        else:
            matches = [word for word in self.wordlist if word.startswith(prefix)]
            if len(matches) == 1: # matched exactly one word in the wordlist
                return matches[0]
            else:
                # exact match not found.
                # this is not a validation routine, just return the input
                return prefix

    def expand(self, mnemonic):
        return ' '.join(map(self.expand_word, mnemonic.split(' ')))

    @classmethod
    def to_seed(cls, mnemonic, passphrase=''):
        mnemonic = cls.normalize_string(mnemonic)
        passphrase = cls.normalize_string(passphrase)
        return PBKDF2(mnemonic, u'mnemonic' + passphrase, iterations=PBKDF2_ROUNDS, macmodule=hmac, digestmodule=hashlib.sha512).read(64)

def string_to_int(s):
    result = 0
    for c in s:
        if not isinstance(c, int):
            c = ord(c)
        result = (result << 8) + c
    return result

def derive(parent_key, parent_chaincode, i, curve):
    assert len(parent_key) == 32
    assert len(parent_chaincode) == 32
    k = parent_chaincode
    if ((i & privdev) != 0):
        key = '\x00' + parent_key
    else:
        key = publickey(parent_key, curve)
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        if curve == 'ed25519':
            break
        #print 'I: ' + binascii.hexlify(h)
        a = string_to_int(key)
        key = (a + string_to_int(parent_key)) % curve.order
        if (a < curve.order and key != 0):
            key = int_to_string(key, 32)
            break
        d = '\x01' + h[32:] + struct.pack('>L', i)
        #print 'a failed: ' + binascii.hexlify(h[:32])
        #print 'RETRY: ' + binascii.hexlify(d)
                        
    return (key, chaincode)


def fingerprint(publickey):
    h = hashlib.new('ripemd160', hashlib.sha256(publickey).digest()).digest()
    return h[:4]

def publickey(private_key, curve):
    if curve == 'ed25519':
        sk = ed25519.SigningKey(private_key)
        return '\x00' + sk.get_verifying_key().to_bytes()
    else:
        Q = string_to_int(private_key) * curve.generator
        xstr = int_to_string(Q.x(), 32)
        parity = Q.y() & 1
        return chr(2 + parity) + xstr

# mode 0 - compatible with BIP32 private derivation
def seed2hdnode(seed, modifier, curve):
    k = seed
    while True:
        h = hmac.new(modifier, seed, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        a = string_to_int(key)
        if (curve == 'ed25519'):
            break
        if (a < curve.order and a != 0):
            break
        seed = h
        #print 'RETRY seed: ' + binascii.hexlify(seed)
    return (key, chaincode)

def nextWord(currSeed, nextPos):
    #print("cs: " + currSeed)
    global seedCount
    global f
    #print "npos :" + str(nextPos)
    if nextPos < len(sys.argv)-1:
      #print(seedStruct[nextPos])
      if len(seedStruct[nextPos]) > 1:
        for x in range(seedStruct[nextPos]['min'],seedStruct[nextPos]['max']+1):
          #print("WordLength: " + str(x) + "------------------------------")
          for theWord in words[x]:
            currSeed += theWord + " "
            nextWord(currSeed, nextPos + 1)
            currSeed = currSeed.strip().rsplit(' ', 1)[0] + " "
      else:
        currSeed += seedStruct[nextPos]['word'] + " "
        nextWord(currSeed, nextPos + 1)
        currSeed = currSeed.strip().rsplit(' ', 1)[0] + " "
        
    else:
      #if len(seedStruct[nextPos]) > 1:
      #  for x in range(seedStruct[nextPos]['min'],seedStruct[nextPos]['max']+1):
      #    print("WordLength: " + str(x) + "------------------------------")
      #    for theWord in words[x]:
      #      currSeed += theWord
      #else:
        #currSeed += seedStruct[nextPos]['word']
      seedCount += 1
      #print("Seed:" + currSeed)
      currSeed = currSeed.strip()
      
      try:
        entropy = binascii.hexlify(m.to_entropy(currSeed))
        seedhex = binascii.hexlify(m.to_seed(currSeed))
        #print("Found valid seed!")
        #print(hexSeed)
        #print("Seed: "+ currSeed)
        
        curve = 'ed25519'
        derivationpath = [privdev + 44, privdev + 501, privdev + 0, privdev +0]
        
        k,c = seed2hdnode(binascii.unhexlify(seedhex), 'ed25519 seed', curve)
        p = publickey(k, curve)
        fpr = '\x00\x00\x00\x00'
        path = 'm'
        #print ''
        #print "Seed (hex): " + seedhex
        #print ''
        #print '* Chain ' + path
        #print '  * fingerprint: ' + binascii.hexlify(fpr)
        #print '  * chain code: ' + binascii.hexlify(c)
        #print '  * private: ' + binascii.hexlify(k)
        #print '  * public: ' + binascii.hexlify(p)
        #addr = b58encode(p[1:])
        #DEBUG
        #print('addr: '+addr+'\n')
        #if addr == searchAddr: #'GzrYzHUJUtKDHWmefBmX68g9BpJRLN9wNsqQKPvwge3W':
        #    output = open('keys_'+str(seedCount)+'.txt', 'w')
        #    output.write('Seed: ' + currSeed+'\n')
        #    output.write('Path: ' + path+'\n')
        #    output.write('Addr: ' + addr+'\n')
        #    output.close()
        #    sys.stdout.write("FOUND IT!!!!!!!!!!!!!!!!\n\n")
        #    print("Seed: " + currSeed)
        #    exit()

        depth=0
        for i in derivationpath:
            depth += 1
            if curve == 'ed25519':
                # no public derivation for ed25519
                i = i | privdev
            fpr = fingerprint(p)
            path = path + "/" + str(i & (privdev-1))
            if ((i & privdev) != 0):
                path = path + "'"
            k,c = derive(k, c, i, curve)
            p = publickey(k, curve) 
            
        #print '* Chain ' + path
        #print '  * fingerprint: ' + binascii.hexlify(fpr)
        #print '  * chain code: ' + binascii.hexlify(c)
        #print '  * private: ' + binascii.hexlify(k)
        #print '  * public: ' + binascii.hexlify(p[1:])
        #print '  * addr: ' + b58encode(p[1:])
        #print    
            if depth == 2 or depth == 4:
                addr = b58encode(p[1:])
                #DEBUG
                #print('path: '+path+'\n')
                #print('addr: '+addr+'\n')
                if addr == searchAddr: #'GzrYzHUJUtKDHWmefBmX68g9BpJRLN9wNsqQKPvwge3W':
                    output = open('keys_'+str(seedCount)+'.txt', 'w')
                    output.write('Seed: ' + currSeed+'\n')
                    output.write('Path: ' + path+'\n')
                    output.write('Addr: ' + addr+'\n')
                    output.close()
                    sys.stdout.write("FOUND IT!!!!!!!!!!!!!!!!\n\n")
                    print("Seed: " + currSeed)
                    exit()
        
      except ValueError:
        if seedCount%1000 == 0:
            sys.stdout.write('.')
        
      
      if seedCount%10000 == 0:
        print(str(seedCount) + ' Seeds ' + str(datetime.now()))
        #f.write((str(seedCount) + ' Seeds ' + str(datetime.now())) +'\n')
      currSeed = currSeed.strip().rsplit(' ', 1)[0] + " "

    

def main():
    import binascii
    import sys
    global m
    m = Mnemonic('english')

    for x in range(1,len(sys.argv)):
      seedStruct.append({'word':sys.argv[x]})
      
    #print(seedStruct)
    
    global f
    global seedCount
    seedCount = 0
    #f = open('log.txt', 'w')

    #starttime = datetime.now()
    #print('Start: ' + str(starttime))
    #f.write('Start: ' + str(starttime) + '\n')
   
    global searchAddr 
    searchAddr = raw_input("Enter Search Address: ")
   
    for x in range(1,len(sys.argv)-1):
        if (seedStruct[x]['word'] == 'x'):
            seedStruct.pop(x)
            seedStruct.insert(x,{'min': 3,'max':8})    
   
    currSeed = ''
    nextWord(currSeed, 0)        
    #seedStruct.pop(x)

    #endtime = datetime.now()
    #f.write('End: ' + str(endtime) + '\n')
    #f.write('Total: ' + str(endtime - starttime)  + '\n')
    #f.close()
    

if __name__ == '__main__':
    main()
