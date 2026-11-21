from adpathfinder.utils.config_loader import load_config
from adpathfinder.utils.logger import setup_logger
from adpathfinder.core.controller import ADPathFinderController


def main():

    print("=" * 45)

    print("       ADPathFinder v1.0")

    print(" Active Directory Security Analyzer")

    print("=" * 45)

    # Load configuration
    config = load_config()

    # Initialize logging
    logger = setup_logger()

    logger.info("Application initialization started")

    # Create controller
    controller = ADPathFinderController(
        config=config,
        logger=logger
    )

    try:

        controller.run()

    except Exception as error:

        logger.error(f"Application error: {error}")

        raise

    finally:

        controller.shutdown()


if __name__ == "__main__":

    main()