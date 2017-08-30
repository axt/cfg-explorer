import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="count", help="increase output verbosity")

    args = parser.parse_args()
    
    print args


if __name__ == '__main__':
    main()
