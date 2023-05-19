// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

//@review againsnt chainlink reference PriceConverter https://docs.chain.link/docs/get-the-latest-price/

error MismatchInBaseAndQuoteDecimals();

contract USDCPriceFeedBNBTestnet {
    AggregatorV3Interface internal priceFeed1;
    AggregatorV3Interface internal priceFeed2;

    constructor() {
        priceFeed1 = AggregatorV3Interface(
            0x2514895c72f50D8bd4B4F9b1110F0D6bD2c97526
        ); // BNB usd
        priceFeed2 = AggregatorV3Interface(
            0x90c069C4538adAc136E051052E14c1cD799C41B7
        ); // USDC usd
    }

    function decimals() public view returns (uint8) {
        return 18;
    }

    function description() public view returns (string memory) {
        return "USDC / BNB";
    }

    function getThePrice() public view returns (int) {
        // If either of the base or quote price feeds have mismatch in decimal then it could be a problem, so throw!
        uint8 decimals1 = priceFeed1.decimals();
        uint8 decimals2 = priceFeed2.decimals();

        if (decimals1 != decimals2) revert MismatchInBaseAndQuoteDecimals();

        /**
         * Returns the latest price of price feed 1
         */

        (
            uint80 roundID1,
            int256 price1,
            ,
            uint256 updatedAt1,
            uint80 answeredInRound1
        ) = priceFeed1.latestRoundData();

        require(price1 > 0, "Chainlink price <= 0");
        // 2 days old price is considered stale since the price is updated every 24 hours
        require(
            updatedAt1 >= block.timestamp - 60 * 60 * 24 * 2,
            "Incomplete round"
        );
        require(answeredInRound1 >= roundID1, "Stale price");
        // price11 = uint192(int192(price1));

        /**
         * Returns the latest price of price feed 2
         */

        (
            uint80 roundID2,
            int256 price2,
            ,
            uint256 updatedAt2,
            uint80 answeredInRound2
        ) = priceFeed2.latestRoundData();

        require(price2 > 0, "Chainlink price <= 0");
        // 2 days old price is considered stale since the price is updated every 24 hours
        require(
            updatedAt2 >= block.timestamp - 60 * 60 * 24 * 2,
            "Incomplete round"
        );
        require(answeredInRound2 >= roundID2, "Stale price");

        // Always using decimals 18 for derived price feeds
        int usdc_BNB = (price2 * (10 ** 18)) / price1;
        return usdc_BNB;
    }
}
