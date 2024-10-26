import { twMerge } from 'tailwind-merge'

export default function Gitbook({ className }: { className?: string }) {
  return (
    <svg
      width="65"
      height="65"
      viewBox="0 0 65 65"
      className={twMerge('fill-current size-6', className)}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path d="M27.3964 34.2196C30.5255 36.0256 32.09 36.9286 33.8083 36.9301C35.5265 36.9316 37.0926 36.0313 40.2249 34.2308L60.1914 22.7535C61.0927 22.2354 61.6484 21.275 61.6484 20.2353C61.6484 19.1956 61.0927 18.2352 60.1914 17.7171L40.2177 6.2356C37.0888 4.43701 35.5243 3.53772 33.8078 3.53839C32.0912 3.53906 30.5275 4.43957 27.4 6.24059L10.2293 16.1286C10.102 16.2019 10.0384 16.2386 9.97908 16.2733C4.11371 19.7069 0.489892 25.9755 0.441438 32.7718C0.440948 32.8405 0.440948 32.9139 0.440948 33.0608C0.440948 33.2074 0.440948 33.2808 0.441437 33.3494C0.489785 40.1381 4.10552 46.4008 9.96044 49.8371C10.0196 49.8718 10.0832 49.9085 10.2102 49.9819L20.9659 56.1919C27.2332 59.8104 30.3668 61.6197 33.8081 61.6209C37.2493 61.622 40.3842 59.8149 46.6539 56.2005L58.008 49.6552C61.1474 47.8454 62.7171 46.9406 63.579 45.4488C64.4409 43.957 64.4409 42.1452 64.4409 38.5215V31.5212C64.4409 30.516 63.8965 29.5896 63.0182 29.1004C62.1684 28.6271 61.1325 28.6341 60.2891 29.1189L37.0074 42.5019C35.4454 43.3998 34.6643 43.8488 33.8073 43.8491C32.9502 43.8493 32.1689 43.4008 30.6063 42.5039L14.8487 33.4587C14.0594 33.0056 13.6647 32.779 13.3477 32.7381C12.625 32.6448 11.9301 33.0497 11.6548 33.7244C11.5341 34.0203 11.5365 34.4754 11.5414 35.3855C11.545 36.0555 11.5468 36.3905 11.6094 36.6987C11.7497 37.3888 12.1127 38.0136 12.6428 38.4772C12.8795 38.6842 13.1696 38.8517 13.75 39.1866L30.5974 48.9103C32.1641 49.8145 32.9474 50.2666 33.8075 50.2669C34.6677 50.2671 35.4513 49.8154 37.0184 48.9121L57.6684 37.0086C58.2037 36.7 58.4714 36.5457 58.6721 36.6617C58.8727 36.7777 58.8727 37.0866 58.8727 37.7045V40.8796C58.8727 41.7856 58.8727 42.2385 58.6572 42.6115C58.4418 42.9844 58.0493 43.2106 57.2644 43.6631L40.2322 53.4811C37.0966 55.2886 35.5288 56.1923 33.8079 56.1915C32.0869 56.1907 30.5199 55.2856 27.386 53.4752L11.4509 44.2702C11.4003 44.2409 11.375 44.2263 11.3514 44.2125C8.01023 42.2601 5.94859 38.6883 5.92925 34.8185C5.92912 34.7912 5.92912 34.762 5.92912 34.7035V31.7889C5.92912 29.6526 7.06689 27.678 8.91513 26.6067C10.5483 25.6601 12.5628 25.6582 14.1977 26.6018L27.3964 34.2196Z" />
    </svg>
  )
}