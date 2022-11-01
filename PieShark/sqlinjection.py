from sqlalchemy import Column, create_engine, MetaData, Table, text
from sqlalchemy.types import String, DateTime, Integer, Text
from sqlalchemy import Table, Column, create_engine, select, insert, update, delete, join
import sqlite3, os
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

_DBNAME_MAP = {
    'psycopg2': 'postgres',
    'MySQLdb': 'mysql',
    'sqlite3': 'sqlite',
    'sqlite': 'sqlite',
    'pysqlite': 'sqlite'
    }

def get_dbname(dbobj):
    mod = dbobj.__class__.__module__.split('.', 1)[0]
    return _DBNAME_MAP.get(mod)


class filter_xss_inject:
	"""docstring for Vuln"""
	def __init__(self, arg):
		super(Vuln, self).__init__()
		self.arg = arg

class db_management:
	"""docstring for db_management"""
	def __init__(self, arg):
		super(db_management, self).__init__()
		self.arg = arg
		

class DB_SECURITY:
	"""docstring for DB_SECURITY"""
	def __init__(self, host, password, dbname):
		super(DB_SECURITY, self).__init__()
		try:
			if int(os.environ.get('DB_TOKEN')) >= 0x999:
				self.host:str = host 
			else:
				self.host:str = ":memory:"
		except:
			self.host:str = ":memory:"
		self.password:bytes = password
		self.dbname:str = dbname
		self.session= {} or dict 

	def db_type(self, session):
		if self.dbname and session:
			numbers = [_x_ for _x_ in range(len(session)) if round(_x_/2)!=0]
			self.session = map(lambda x: x + x, numbers)
		print(self.connect)
		return get_dbname(self.connect), list(self.session)

	def sqlite_manager(self, database):
		self.connect = database
		get_type, session = self.db_type(self.host)
		print(get_type, session)





from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


import gzip

##creating key

def key_creation(password):

    kdf=PBKDF2HMAC(algorithm = hashes.SHA256(), salt=b'\xfaz\xb5\xf2|\xa1z\xa9\xfe\xd1F@1\xaa\x8a\xc2', iterations=1024, length=32, backend=default_backend())

    key=Fernet(base64.urlsafe_b64encode(kdf.derive(password)))

    return key

def save_file(con,password):
    b=b''
    try:
    	for line in con.iterdump():
    		b+=bytes('%s\n','utf8') % bytes(line,'utf8')
    except:
    	with con.begin() as c:
    		db_Api = c.connection
    		for line in db_Api.iterdump():
    			b+=bytes('%s\n','utf8') % bytes(line,'utf8')
    key = key_creation(password)
    content = key.encrypt(b)
    return content

def decrypt_files(con, password):
    key = key_creation(password)
    content= key.decrypt(con)
    return content.decode('utf-8')

_home_path_ , filename = os.path.split(os.path.abspath(__file__).replace("\\", "/"))
#app = DB_SECURITY(host=f"sqlite+pysqlite:///{_home_path_}/tera_search.db", password='23ddew', dbname='Base')
#database = sqlite3.connect("tera_search.db")
#app.sqlite_manager(database)

password=b'Sw0rdFish'
name_db = "tera_search"
port_ = 80

conn = create_engine(f"sqlite+pysqlite:///{_home_path_}/{name_db}.db")
save_files = save_file(conn, password)

decrypt = decrypt_files(save_files, password)

database = create_engine(f"sqlite+pysqlite:///:memory:")
with database.begin() as conn:
                dbapi_conn =  conn.connection
                dbapi_conn.executescript(decrypt)
                cursor = dbapi_conn.cursor()
                cursor.execute("UPDATE Tera_Search SET keyword='Help' WHERE keyword LIKE '%Hello%'")
                cursor.execute("SELECT * FROM Tera_Search")
                print(cursor.fetchall())
                try:
                        conn.rollback()
                        print(1)
                except:
                        cursor.execute('ROLLBACK')
                        print(2)

                cursor.execute("SELECT * FROM Tera_Search")
                print(cursor.fetchall())



def save_file(con, dbname, password):
    b=b''
    try:
        for line in con.iterdump():
            b+=bytes('%s\n','utf8') % bytes(line,'utf8')
    except:
        with con.begin() as c:
            db_Api = c.connection
            for line in db_Api.iterdump():
                b+=bytes('%s\n','utf8') % bytes(line,'utf8')
    key = key_creation(password)
    content = key.encrypt(b)
    with gzip.open(getcwd()+dbname+'_crypted.sql.gz','wb') as w:
        w.write(content)

def decrypt_files(con, dbname, password):
    with gzip.open(getcwd()+dbname+'_crypted.sql.gz','rb') as r:
        content = r.read()
    key = key_creation(password)
    content= key.decrypt(content)
    return content.decode('utf-8')

class DB_SQLITE(object):
    """docstring for DB_SQLITE"""
    def __init__(self, dbname, port, password):
        super(DB_SQLITE, self).__init__()
        self.password = password
        self.dbname = dbname

    def save_files(self, conn):
        return save_files(conn, dbname=self.dbname, password=self.password)
    def sql(sel, conn):
        try:
            sql = decrypt_files(self.conn, dbname=self.dbname, password=self.password)
        except:
            sql = ''
        return sql
    def saved(self, pre):
        sql = pre
#with database.begin() as conn:
#	dbapi_conn = conn.connection
#	dbapi_conn.executescript(decrypt)
	
#	dbapi_conn.execute("UPDATE Tera_Search SET keyword='Help' WHERE keyword LIKE '%Hello%'")
#	cursor = dbapi_conn.execute("SELECT * FROM Tera_Search")
#	print(cursor.fetchall())
 #       saved = ""

    
    #for xx in dbapi_conn.iterdump():
       # saved += xx
    #print(saved)

#	print(dbapi_conn)
##### start
#### [db select]
#### [proces]
#### [save]
####
###



#print(decrypt_files(save_files, password))
#print(conn.raw_connection().connection.iterdump)

#save_cdb(conn,'tera_search',password)
#conn.close()
#conn = open_cdb('tera_search',password)
#print(conn)
#connection = database.raw_connection()
#cursor = connection.cursor()
#cursor.execute('select * from Tera_Search')
#print(cursor.fetchall())