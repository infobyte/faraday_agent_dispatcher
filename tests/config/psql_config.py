import os
from configparser import ConfigParser, DuplicateSectionError

if __name__ == '__main__':
    connection_string = 'postgresql+psycopg2://{username}:{password}@postgres/{database}'.format(
        username=os.environ['POSTGRES_USER'],
        password=os.environ['POSTGRES_PASSWORD'],
        database=os.environ['POSTGRES_DB'],
    )
    faraday_config = ConfigParser()
    config_path = os.path.expanduser('~/.faraday/config/server.ini')
    faraday_config.read(config_path)
    try:
        faraday_config.add_section('database')
    except DuplicateSectionError:
        pass
    faraday_config.set('database', 'connection_string', connection_string)
    with open(config_path, 'w') as faraday_config_file:
        faraday_config.write(faraday_config_file)