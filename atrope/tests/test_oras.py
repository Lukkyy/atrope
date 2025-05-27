# import oras.provider

# registry = oras.provider.Registry("192.168.0.165", insecure=True, tls_verify=False)
# result_login = registry.login(username="admin", password="Harbor12345")
# print(result_login)
# result_pull = registry.pull(target="myproject/oci-alpine:v1")
# print(result_pull)
import oras.provider
from oras.logger import logger, setup_logger

setup_logger(quiet=False, debug=True)

registry = oras.provider.Registry(
    "192.168.0.165", insecure=True, tls_verify=False, auth_backend="basic"
)

# Other ways to handle login:
# client.set_basic_auth(username, password)
# client.set_token_auth(token)

try:
    registry.login(username="admin", password="Harbor12345")
    result_pull = registry.pull(
        target="myproject/oci_alpine:latest", outdir="/home/lukas-moder/Desktop"
    )
    print(result_pull)
    logger.info(result_pull)
except Exception as e:
    logger.exit(str(e))
