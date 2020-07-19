قمرشليلهrobot
# dnsviz
https://dnsviz.net/d/vip/dnssec/
<html>
<head>
    <meta name="viewport" content="width=device-width">
    
    <script src=file:///android_asset/app.js></script>
    <script src="file:///android_asset/Libs/JQuery.js"></script>
    <script src="file:///android_asset/Libs/Flot.js"></script>
</head>
	
<script>
    //Initialise variables.        
    sampleCount = 100;                
    updateInterval = 10;   
    sensorData = null;

    //Called when document is loaded.
    function OnStart()
    {
        //Lock screen orientation to Landscape.
        //(Callback draws the page after the orientation change completes)
        app.SetOrientation( "Landscape", DrawPage );
        
        //Create and start accelerometer sensor.
    	sns = app.CreateSensor( "Accelerometer", "Fast" );
    	sns.Start();
    }
    
    //Draw the HTML page.
    function DrawPage()
    {
        //Set graph options
        var options =
        {
            grid: { color: "#656565", borderWidth: 1 },
            series: { shadowSize: 0  },
            yaxis: { min: -20, max: 20 },
            xaxis: { max: 0, min: -sampleCount, show: false }
        }
       
        //Get data and plot the graph.
        var vals = sns.GetValues();
        var series = GetSeries( sampleCount, [vals[1],vals[2],vals[3]] );
        plot = $.plot("#placeholder", series, options );
       
        //Start updating the graph.
        Update();
    }
   
    //Update the graph.
    function Update()
    {
        //Get more data.
        var vals = sns.GetValues();
        var series = GetSeries( sampleCount, [vals[1],vals[2],vals[3]] );
       
        //Re-plot the graph.
        plot.setData( series );                   
        plot.draw();
       
        //Call this function again.
        setTimeout( Update, updateInterval );
    }
   
    //Get accumulated data series.
    function GetSeries( points, funcs )
    {                                 
        if( typeof flt
